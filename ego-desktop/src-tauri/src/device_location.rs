use crate::app::Location;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CITIES: &str = include_str!("../data/cities.tsv");
const RECHECK: Duration = Duration::from_secs(30 * 60);
const FAILED_RECHECK: Duration = Duration::from_secs(10 * 60);
const IP_RECHECK: Duration = Duration::from_secs(6 * 3600);
const MAX_CITY_KM: f64 = 250.0;
pub const SOURCE_DEVICE: &str = "device";
pub const SOURCE_IP: &str = "ip";

struct City {
    lat: f64,
    lon: f64,
    name: &'static str,
    region: &'static str,
    country: &'static str,
}

fn cities() -> &'static [City] {
    static LIST: OnceCell<Vec<City>> = OnceCell::new();
    LIST.get_or_init(|| {
        let mut countries: HashMap<&'static str, &'static str> = HashMap::new();
        let mut out = Vec::new();
        for line in CITIES.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(rest) = line.strip_prefix('#') {
                if let Some((code, name)) = rest.split_once('\t') {
                    countries.insert(code, name);
                }
                continue;
            }
            let mut f = line.split('\t');
            let (Some(lat), Some(lon), Some(name), Some(region), Some(code)) =
                (f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let (Ok(lat), Ok(lon)) = (lat.parse::<i32>(), lon.parse::<i32>()) else { continue };
            let Some(country) = countries.get(code).copied() else { continue };
            out.push(City { lat: lat as f64 / 100.0, lon: lon as f64 / 100.0, name, region, country });
        }
        out
    })
}

fn distance_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    6_371.0 * 2.0 * a.sqrt().min(1.0).asin()
}

pub fn nearest_city(lat: f64, lon: f64) -> Option<Location> {
    if !lat.is_finite() || !lon.is_finite() || lat.abs() > 90.0 || lon.abs() > 180.0 {
        return None;
    }
    let (km, city) = cities()
        .iter()
        .map(|c| (distance_km(lat, lon, c.lat, c.lon), c))
        .min_by(|a, b| a.0.total_cmp(&b.0))?;
    if km > MAX_CITY_KM {
        return None;
    }
    Some(Location {
        latitude: city.lat,
        longitude: city.lon,
        accuracy: None,
        altitude: None,
        city: Some(city.name.to_string()),
        region: (!city.region.is_empty()).then(|| city.region.to_string()),
        country: Some(city.country.to_string()),
        source: Some(SOURCE_DEVICE.to_string()),
    })
}

#[cfg(windows)]
fn read_position() -> Option<(f64, f64)> {
    use windows::Devices::Geolocation::Geolocator;
    use windows::Foundation::TimeSpan;
    let locator = Geolocator::new().ok()?;
    let pos = locator
        .GetGeopositionAsyncWithAgeAndTimeout(
            TimeSpan::from(Duration::from_secs(10 * 60)),
            TimeSpan::from(Duration::from_secs(15)),
        )
        .ok()?
        .join()
        .ok()?
        .Coordinate()
        .ok()?
        .Point()
        .ok()?
        .Position()
        .ok()?;
    Some((pos.Latitude, pos.Longitude))
}

#[cfg(not(windows))]
fn read_position() -> Option<(f64, f64)> {
    None
}

fn number(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn ipinfo_point(v: &serde_json::Value) -> Option<(f64, f64)> {
    let (lat, lon) = v.get("loc")?.as_str()?.split_once(',')?;
    Some((lat.trim().parse().ok()?, lon.trim().parse().ok()?))
}

fn latlon_point(v: &serde_json::Value) -> Option<(f64, f64)> {
    if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
        return None;
    }
    Some((number(v.get("latitude")?)?, number(v.get("longitude")?)?))
}

async fn fetch_point(client: &reqwest::Client, url: &str, read: fn(&serde_json::Value) -> Option<(f64, f64)>) -> Option<(f64, f64)> {
    let v: serde_json::Value = client.get(url).send().await.ok()?.json().await.ok()?;
    read(&v)
}

pub fn agreed_city(points: &[(f64, f64)]) -> Option<Location> {
    let mut tally: Vec<(Location, usize)> = Vec::new();
    for &(lat, lon) in points {
        let Some(loc) = nearest_city(lat, lon) else { continue };
        match tally.iter_mut().find(|(l, _)| l.city == loc.city && l.region == loc.region && l.country == loc.country) {
            Some((_, n)) => *n += 1,
            None => tally.push((loc, 1)),
        }
    }
    let best = tally.iter().map(|(_, n)| *n).max()?;
    let (mut loc, _) = tally.into_iter().find(|(_, n)| *n == best)?;
    loc.source = Some(SOURCE_IP.to_string());
    Some(loc)
}

pub async fn ip_city(client: &reqwest::Client, ip: &str, ip_api: Option<(f64, f64)>) -> Option<Location> {
    static LAST: Mutex<Option<(String, Instant, Location)>> = Mutex::new(None);
    if let Some((seen, at, loc)) = LAST.lock().ok().and_then(|g| g.clone()) {
        if seen == ip && at.elapsed() < IP_RECHECK {
            return Some(loc);
        }
    }
    let (a, b, c) = tokio::join!(
        fetch_point(client, "https://ipinfo.io/json", ipinfo_point),
        fetch_point(client, "https://get.geojs.io/v1/ip/geo.json", latlon_point),
        fetch_point(client, "https://ipwho.is/", latlon_point),
    );
    let points: Vec<(f64, f64)> = [a, b, c, ip_api].into_iter().flatten().collect();
    let found = agreed_city(&points)?;
    if let Ok(mut g) = LAST.lock() {
        *g = Some((ip.to_string(), Instant::now(), found.clone()));
    }
    Some(found)
}

pub async fn device_city() -> Option<Location> {
    static LAST: Mutex<Option<(Instant, Option<Location>)>> = Mutex::new(None);
    if let Some((at, found)) = LAST.lock().ok().and_then(|g| g.clone()) {
        let wait = if found.is_some() { RECHECK } else { FAILED_RECHECK };
        if at.elapsed() < wait {
            return found;
        }
    }
    let found = tokio::task::spawn_blocking(|| read_position().and_then(|(lat, lon)| nearest_city(lat, lon)))
        .await
        .ok()
        .flatten();
    if let Ok(mut g) = LAST.lock() {
        *g = Some((Instant::now(), found.clone()));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_city_table_loads_with_a_country_name_for_every_city() {
        let list = cities();
        assert!(list.len() > 30_000, "only {} cities loaded", list.len());
        assert!(list.iter().all(|c| !c.country.is_empty() && c.country.len() > 2));
    }

    #[test]
    fn a_position_in_calgary_names_calgary_not_edmonton() {
        let loc = nearest_city(51.0447, -114.0719).expect("a city");
        assert_eq!(loc.city.as_deref(), Some("Calgary"));
        assert_eq!(loc.region.as_deref(), Some("Alberta"));
        assert_eq!(loc.country.as_deref(), Some("Canada"));
        assert_eq!(loc.source.as_deref(), Some(SOURCE_DEVICE));
    }

    #[test]
    fn the_shared_coordinates_are_the_city_centre_not_the_device() {
        let home = (51.1301, -114.2087);
        let loc = nearest_city(home.0, home.1).expect("a city");
        assert_eq!((loc.latitude, loc.longitude), (51.05, -114.09));
        assert!(distance_km(home.0, home.1, loc.latitude, loc.longitude) > 5.0);
    }

    #[test]
    fn other_places_resolve_to_their_own_city() {
        assert_eq!(nearest_city(53.5461, -113.4938).and_then(|l| l.city).as_deref(), Some("Edmonton"));
        assert_eq!(nearest_city(52.5200, 13.4050).and_then(|l| l.city).as_deref(), Some("Berlin"));
        assert_eq!(nearest_city(42.6629, 21.1655).and_then(|l| l.city).as_deref(), Some("Pristina"));
    }

    #[test]
    #[ignore]
    fn print_this_computers_city() {
        let found = read_position().and_then(|(lat, lon)| nearest_city(lat, lon));
        println!("device city: {:?}", found.map(|l| (l.city, l.region, l.country)));
    }

    #[test]
    fn the_ip_city_is_the_one_most_lookups_agree_on() {
        let edmonton = (53.4593, -113.6546);
        let calgary = (51.0501, -114.0853);
        let loc = agreed_city(&[calgary, (51.1564, -114.0566), calgary, edmonton]).expect("a city");
        assert_eq!(loc.city.as_deref(), Some("Calgary"));
        assert_eq!(loc.source.as_deref(), Some(SOURCE_IP));
        assert_eq!(agreed_city(&[calgary, edmonton]).and_then(|l| l.city).as_deref(), Some("Calgary"), "a tie goes to the first lookup");
        assert_eq!(agreed_city(&[edmonton]).and_then(|l| l.city).as_deref(), Some("Edmonton"));
        assert!(agreed_city(&[]).is_none());
    }

    #[test]
    fn each_lookup_answer_is_read_in_its_own_shape() {
        let info = serde_json::json!({"city": "Calgary", "loc": "51.0501,-114.0853"});
        assert_eq!(ipinfo_point(&info), Some((51.0501, -114.0853)));
        let geojs = serde_json::json!({"latitude": "51.1564", "longitude": "-114.0566"});
        assert_eq!(latlon_point(&geojs), Some((51.1564, -114.0566)));
        let who = serde_json::json!({"success": true, "latitude": 51.05, "longitude": -114.08});
        assert_eq!(latlon_point(&who), Some((51.05, -114.08)));
        assert_eq!(latlon_point(&serde_json::json!({"success": false, "latitude": 1.0, "longitude": 2.0})), None);
    }

    #[tokio::test]
    #[ignore]
    async fn print_this_connections_ip_city() {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
        let found = ip_city(&client, "test", None).await;
        println!("ip city: {:?}", found.map(|l| (l.city, l.region, l.country)));
    }

    #[test]
    fn nonsense_or_remote_positions_give_no_city() {
        assert!(nearest_city(f64::NAN, 0.0).is_none());
        assert!(nearest_city(95.0, 0.0).is_none());
        assert!(nearest_city(0.0, 0.0).is_none());
        assert!(nearest_city(-48.8767, -123.3933).is_none());
    }
}
