use crate::chain_db::{ComputeCapacityOffer, ComputeReservation};
use std::collections::BTreeMap;
use std::sync::Mutex;

const CLOCK_SKEW_SECS: i64 = 300;
const KEEP_ENDED_SECS: i64 = 86_400;

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Book {
    #[serde(default)]
    offers: BTreeMap<String, ComputeCapacityOffer>,
    #[serde(default)]
    admitted: BTreeMap<String, ComputeReservation>,
}

static BOOK_LOCK: Mutex<()> = Mutex::new(());

fn book_path() -> std::path::PathBuf {
    crate::ledger::data_dir().join("compute_provider.json")
}

fn load() -> Book {
    std::fs::read(book_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn store(book: &Book) -> Result<(), String> {
    let bytes = serde_json::to_vec(book).map_err(|e| e.to_string())?;
    crate::utils::atomic_write(&book_path(), &bytes)
        .map_err(|e| format!("Could not save this machine's rental book: {e}"))
}

pub fn list_offer(offer: &ComputeCapacityOffer) -> Result<(), String> {
    let _held = BOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut book = load();
    book.offers.insert(offer.offer_id.clone(), offer.clone());
    store(&book)
}

pub fn withdraw_offer(offer_id: &str) {
    let _held = BOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut book = load();
    if book.offers.remove(offer_id).is_some() {
        let _ = store(&book);
    }
}

pub fn is_own_offer(offer_id: &str) -> bool {
    let _held = BOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    load().offers.contains_key(offer_id)
}

pub fn end(reservation_id: &str, now: i64) {
    let _held = BOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut book = load();
    if let Some(r) = book.admitted.get_mut(reservation_id) {
        if r.expires_at > now {
            r.expires_at = now;
            r.status = "terminated".to_string();
            let _ = store(&book);
        }
    }
}

pub fn admit(
    reservation_id: &str,
    claimed: Option<&ComputeReservation>,
    renter: &str,
    me: &str,
    now: i64,
) -> Result<ComputeReservation, String> {
    let _held = BOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut book = load();
    let (admitted, fresh) = decide(&book, reservation_id, claimed, renter, me, now)?;
    if fresh {
        book.admitted.retain(|_, r| r.expires_at.saturating_add(KEEP_ENDED_SECS) > now);
        book.admitted.insert(admitted.reservation_id.clone(), admitted.clone());
        store(&book)?;
    }
    Ok(admitted)
}

fn decide(
    book: &Book,
    reservation_id: &str,
    claimed: Option<&ComputeReservation>,
    renter: &str,
    me: &str,
    now: i64,
) -> Result<(ComputeReservation, bool), String> {
    if let Some(known) = book.admitted.get(reservation_id) {
        if !crate::p2p::exec_addrs_match(&known.buyer_address, renter) {
            return Err("This key does not belong to the renter of this machine.".into());
        }
        if known.expires_at <= now {
            return Err("This rental has ended.".into());
        }
        return Ok((known.clone(), false));
    }

    let res = claimed.ok_or("This machine has no record of that rental.")?;
    if res.reservation_id != reservation_id {
        return Err("The rental id in the request does not match the rental.".into());
    }
    if !crate::p2p::exec_addrs_match(&res.buyer_address, renter) {
        return Err("This key does not belong to the renter of this machine.".into());
    }
    if !crate::p2p::exec_addrs_match(&res.provider_address, me) {
        return Err("This rental is for a different machine.".into());
    }
    if res.status != "active" {
        return Err(format!("This rental is {}.", res.status));
    }
    let offer = book
        .offers
        .get(&res.offer_id)
        .ok_or("This machine never listed the offer this rental names.")?;
    if (res.cpu_cores, res.ram_gb, res.gpu_count) != (offer.cpu_cores, offer.ram_gb, offer.gpu_count) {
        return Err("The rental asks for different hardware than the offer lists.".into());
    }
    let minutes = res.duration_minutes;
    if minutes < offer.min_duration_hours.saturating_mul(60)
        || minutes > offer.max_duration_hours.saturating_mul(60)
    {
        return Err("The rental length is outside what the offer allows.".into());
    }
    if res.total_cost_uegoc < listed_price(offer, minutes, res.paid_in_egusd) {
        return Err("The rental pays less than the listed price.".into());
    }
    if res.created_at < offer.created_at - CLOCK_SKEW_SECS || res.created_at > now + CLOCK_SKEW_SECS {
        return Err("The rental was booked at an impossible time.".into());
    }
    let longest = i64::try_from(minutes).unwrap_or(i64::MAX).saturating_mul(60);
    let expires_at = res.expires_at.min(now.saturating_add(longest));
    if expires_at <= now {
        return Err("This rental has ended.".into());
    }
    if book.admitted.values().any(|r| r.offer_id == res.offer_id && r.expires_at > now) {
        return Err("Someone else is renting this machine right now.".into());
    }

    let mut admitted = res.clone();
    admitted.expires_at = expires_at;
    Ok((admitted, true))
}

fn listed_price(offer: &ComputeCapacityOffer, minutes: u64, in_credits: bool) -> u64 {
    let (per_gpu, per_core) = if in_credits {
        (offer.price_per_gpu_hour_credits, offer.price_per_core_hour_credits)
    } else {
        (offer.price_per_gpu_hour_uegoc, offer.price_per_core_hour_uegoc)
    };
    let hourly = per_gpu
        .saturating_mul(offer.gpu_count as u64)
        .saturating_add(per_core.saturating_mul(offer.cpu_cores as u64));
    hourly.saturating_mul(minutes) / 60
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "egot1provider";
    const RENTER: &str = "egot1renter";
    const NOW: i64 = 1_800_000_000;

    fn offer(id: &str) -> ComputeCapacityOffer {
        ComputeCapacityOffer {
            offer_id: id.into(),
            provider_address: ME.into(),
            cpu_cores: 4,
            ram_gb: 16,
            gpu_count: 1,
            gpu_vram_gb: 24,
            gpu_name: "RTX".into(),
            price_per_gpu_hour_uegoc: 2_000_000,
            price_per_core_hour_uegoc: 100_000,
            price_per_gpu_hour_credits: 100,
            price_per_core_hour_credits: 5,
            price_per_gpu_day_uegoc: 0,
            price_per_core_day_uegoc: 0,
            min_duration_hours: 1,
            max_duration_hours: 48,
            sla_uptime_pct: 99,
            available_from: NOW - 3_600,
            status: "open".into(),
            created_at: NOW - 3_600,
            bonded: false,
        }
    }

    fn rental(id: &str, offer_id: &str) -> ComputeReservation {
        ComputeReservation {
            reservation_id: id.into(),
            offer_id: offer_id.into(),
            buyer_address: RENTER.into(),
            provider_address: ME.into(),
            cpu_cores: 4,
            ram_gb: 16,
            gpu_count: 1,
            duration_minutes: 120,
            period_minutes: 60,
            period_rate_uegoc: 2_400_000,
            total_cost_uegoc: 4_800_000,
            collateral_uegoc: 0,
            status: "active".into(),
            created_at: NOW - 60,
            expires_at: NOW - 60 + 7_200,
            last_heartbeat_at: NOW - 60,
            periods_paid: 0,
            breach_count: 0,
            escrow_remaining: 4_800_000,
            days: 0,
            days_paid: 0,
            daily_rate_uegoc: 0,
            started_at: None,
            paid_in_egusd: false,
        }
    }

    fn book() -> Book {
        let mut b = Book::default();
        b.offers.insert("o1".into(), offer("o1"));
        b
    }

    fn try_admit(b: &Book, r: &ComputeReservation) -> Result<(ComputeReservation, bool), String> {
        decide(b, &r.reservation_id, Some(r), RENTER, ME, NOW)
    }

    #[test]
    fn a_rental_of_a_listed_machine_is_admitted() {
        let (r, fresh) = try_admit(&book(), &rental("r1", "o1")).unwrap();
        assert!(fresh);
        assert_eq!(r.expires_at, NOW - 60 + 7_200);
    }

    #[test]
    fn a_request_without_a_rental_is_refused() {
        let err = decide(&book(), "r1", None, RENTER, ME, NOW).unwrap_err();
        assert!(err.contains("no record"), "{err}");
    }

    #[test]
    fn an_offer_this_machine_never_listed_is_refused() {
        let err = try_admit(&book(), &rental("r1", "forged")).unwrap_err();
        assert!(err.contains("never listed"), "{err}");
        assert!(try_admit(&Book::default(), &rental("r1", "o1")).is_err());
    }

    #[test]
    fn a_rental_naming_another_machine_is_refused() {
        let mut r = rental("r1", "o1");
        r.provider_address = "egot1someoneelse".into();
        assert!(try_admit(&book(), &r).unwrap_err().contains("different machine"));
    }

    #[test]
    fn only_the_renter_key_can_use_a_rental() {
        let r = rental("r1", "o1");
        let err = decide(&book(), "r1", Some(&r), "egot1stranger", ME, NOW).unwrap_err();
        assert!(err.contains("does not belong"), "{err}");

        let mut b = book();
        b.admitted.insert("r1".into(), r.clone());
        assert!(decide(&b, "r1", None, "egot1stranger", ME, NOW).is_err());
        assert!(decide(&b, "r1", None, RENTER, ME, NOW).is_ok());
    }

    #[test]
    fn terms_must_match_the_listing() {
        let b = book();
        let mut more = rental("r1", "o1");
        more.cpu_cores = 64;
        assert!(try_admit(&b, &more).unwrap_err().contains("different hardware"));

        let mut cheap = rental("r1", "o1");
        cheap.total_cost_uegoc = 1;
        assert!(try_admit(&b, &cheap).unwrap_err().contains("less than the listed price"));

        let mut long = rental("r1", "o1");
        long.duration_minutes = 49 * 60;
        assert!(try_admit(&b, &long).unwrap_err().contains("length"));

        let mut early = rental("r1", "o1");
        early.created_at = NOW - 86_400;
        assert!(try_admit(&b, &early).unwrap_err().contains("impossible time"));

        let mut ended = rental("r1", "o1");
        ended.status = "terminated".into();
        assert!(try_admit(&b, &ended).is_err());
    }

    #[test]
    fn credit_rentals_are_priced_in_credits() {
        let mut r = rental("r1", "o1");
        r.paid_in_egusd = true;
        r.total_cost_uegoc = (100 + 4 * 5) * 2;
        assert!(try_admit(&book(), &r).is_ok());
        r.total_cost_uegoc -= 1;
        assert!(try_admit(&book(), &r).is_err());
    }

    #[test]
    fn a_claimed_expiry_cannot_outlast_the_rental() {
        let mut r = rental("r1", "o1");
        r.expires_at = NOW + 365 * 86_400;
        let (admitted, _) = try_admit(&book(), &r).unwrap();
        assert_eq!(admitted.expires_at, NOW + 120 * 60);
    }

    #[test]
    fn one_renter_holds_a_machine_at_a_time() {
        let mut b = book();
        b.admitted.insert("r1".into(), rental("r1", "o1"));
        let err = try_admit(&b, &rental("r2", "o1")).unwrap_err();
        assert!(err.contains("Someone else"), "{err}");

        b.admitted.get_mut("r1").unwrap().expires_at = NOW;
        assert!(try_admit(&b, &rental("r2", "o1")).is_ok());
    }

    #[test]
    fn an_admitted_rental_keeps_its_original_terms() {
        let mut b = book();
        b.admitted.insert("r1".into(), rental("r1", "o1"));
        let mut changed = rental("r1", "o1");
        changed.cpu_cores = 64;
        changed.expires_at = NOW + 365 * 86_400;
        let (r, fresh) = try_admit(&b, &changed).unwrap();
        assert!(!fresh);
        assert_eq!(r.cpu_cores, 4);
        assert_eq!(r.expires_at, NOW - 60 + 7_200);

        b.admitted.get_mut("r1").unwrap().expires_at = NOW - 1;
        assert!(try_admit(&b, &changed).unwrap_err().contains("ended"));
    }
}
