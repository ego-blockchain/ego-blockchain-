use crate::app::Location;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CITIES: &str = include_str!("../data/cities.tsv");
const RECHECK: Duration = Duration::from_secs(30 * 60);
const FAILED_RECHECK: Duration = Duration::from_secs(10 * 60);
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
    fn nonsense_or_remote_positions_give_no_city() {
        assert!(nearest_city(f64::NAN, 0.0).is_none());
        assert!(nearest_city(95.0, 0.0).is_none());
        assert!(nearest_city(0.0, 0.0).is_none());
        assert!(nearest_city(-48.8767, -123.3933).is_none());
    }
}
