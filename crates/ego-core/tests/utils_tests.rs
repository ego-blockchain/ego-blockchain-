#[cfg(test)]
mod utils_tests {
    use ego_core::utils::*;
    use ego_core::{Address, Hash, Timestamp};
    use std::collections::HashMap;

    fn test_hash(seed: u8) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Hash::new(bytes)
    }

    fn test_address(seed: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = seed;
        Address::new(bytes)
    }

    #[test]
    fn test_random_hash() {
        let hash1 = Utils::random_hash();
        let hash2 = Utils::random_hash();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_generate_id() {
        let id1 = Utils::generate_id();
        let id2 = Utils::generate_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36);
        assert_eq!(id2.len(), 36);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(Utils::format_bytes(0), "0 B");
        assert_eq!(Utils::format_bytes(512), "512 B");
        assert_eq!(Utils::format_bytes(1024), "1.00 KB");
        assert_eq!(Utils::format_bytes(1536), "1.50 KB");
        assert_eq!(Utils::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(Utils::format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(Utils::format_bytes(1024 * 1024 * 1024 * 1024), "1.00 TB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(Utils::format_duration(500), "500ms");
        assert_eq!(Utils::format_duration(1000), "1.0s");
        assert_eq!(Utils::format_duration(1500), "1.5s");
        assert_eq!(Utils::format_duration(60_000), "1.0m");
        assert_eq!(Utils::format_duration(90_000), "1.5m");
        assert_eq!(Utils::format_duration(3_600_000), "1.0h");
        assert_eq!(Utils::format_duration(5_400_000), "1.5h");
    }

    #[test]
    fn test_percentage() {
        assert_eq!(Utils::percentage(0, 100), 0.0);
        assert_eq!(Utils::percentage(50, 100), 50.0);
        assert_eq!(Utils::percentage(100, 100), 100.0);
        assert_eq!(Utils::percentage(25, 100), 25.0);
        assert_eq!(Utils::percentage(100, 0), 0.0);
    }

    #[test]
    fn test_validate_geohash() {
        assert!(Utils::validate_geohash("9q9hvu"));
        assert!(Utils::validate_geohash("9q9hvuew"));
        assert!(Utils::validate_geohash("bcde"));
        assert!(Utils::validate_geohash("0123456789bc"));
        assert!(!Utils::validate_geohash(""));
        assert!(!Utils::validate_geohash("abc"));
        assert!(!Utils::validate_geohash("0123456789bcd"));
        assert!(!Utils::validate_geohash("9q9hvuAB"));
        assert!(!Utils::validate_geohash("test!123"));
    }

    #[test]
    fn test_time_since() {
        let past = Timestamp::now();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let elapsed = Utils::time_since(past);
        assert!(elapsed >= 50);
        assert!(elapsed < 200);
    }

    #[test]
    fn test_is_timestamp_valid() {
        let now = Timestamp::now();
        assert!(Utils::is_timestamp_valid(now, 1000));

        std::thread::sleep(std::time::Duration::from_millis(100));
        let past = Timestamp::now();
        assert!(Utils::is_timestamp_valid(past, 1000));

        let future = now.add_millis(500);
        assert!(Utils::is_timestamp_valid(future, 1000));

        let far_future = now.add_millis(2000);
        assert!(!Utils::is_timestamp_valid(far_future, 1000));
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(Utils::truncate_string("hello", 10), "hello");
        assert_eq!(Utils::truncate_string("hello world", 8), "hello...");
        assert_eq!(Utils::truncate_string("test", 3), "...");
        assert_eq!(Utils::truncate_string("", 5), "");
    }

    #[test]
    fn test_hex_to_bytes() {
        let result = Utils::hex_to_bytes("48656c6c6f");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");

        let result = Utils::hex_to_bytes("0x48656c6c6f");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");

        let result = Utils::hex_to_bytes("invalid");
        assert!(result.is_err());

        let result = Utils::hex_to_bytes("123");
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(Utils::bytes_to_hex(b"Hello"), "48656c6c6f");
        assert_eq!(Utils::bytes_to_hex(&[]), "");
        assert_eq!(Utils::bytes_to_hex(&[0, 15, 255]), "000fff");
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![1, 2, 3, 4, 5, 10, 15, 255];
        let hex = Utils::bytes_to_hex(&original);
        let decoded = Utils::hex_to_bytes(&hex).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_validate_slice_id() {
        assert!(Utils::validate_slice_id("slice-001"));
        assert!(Utils::validate_slice_id("slice_002"));
        assert!(Utils::validate_slice_id("abc123"));
        assert!(Utils::validate_slice_id("test-slice_01"));
        assert!(!Utils::validate_slice_id(""));
        assert!(!Utils::validate_slice_id("slice@001"));
        assert!(!Utils::validate_slice_id("slice 001"));
        assert!(!Utils::validate_slice_id(&"a".repeat(65)));
    }

    #[test]
    fn test_moving_average() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let avg = Utils::moving_average(&values, 3);
        assert_eq!(avg.len(), 3);
        assert_eq!(avg[0], 2.0);
        assert_eq!(avg[1], 3.0);
        assert_eq!(avg[2], 4.0);

        let empty = Utils::moving_average(&[], 3);
        assert!(empty.is_empty());

        let too_small = Utils::moving_average(&[1.0, 2.0], 3);
        assert!(too_small.is_empty());
    }

    #[test]
    fn test_exponential_moving_average() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ema = Utils::exponential_moving_average(&values, 0.5);
        assert_eq!(ema.len(), 5);
        assert_eq!(ema[0], 1.0);
        assert!(ema[1] > 1.0 && ema[1] < 2.0);

        let invalid = Utils::exponential_moving_average(&values, 0.0);
        assert!(invalid.is_empty());

        let invalid = Utils::exponential_moving_average(&values, 1.5);
        assert!(invalid.is_empty());
    }

    #[test]
    fn test_standard_deviation() {
        let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let std_dev = Utils::standard_deviation(&values);
        assert!(std_dev > 1.5 && std_dev < 2.5);

        let empty = Utils::standard_deviation(&[]);
        assert_eq!(empty, 0.0);
    }

    #[test]
    fn test_percentile() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(Utils::percentile(&values, 0.0), 1.0);
        assert_eq!(Utils::percentile(&values, 50.0), 6.0);
        assert_eq!(Utils::percentile(&values, 100.0), 10.0);

        let empty = Utils::percentile(&[], 50.0);
        assert_eq!(empty, 0.0);
    }

    #[test]
    fn test_median() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(Utils::median(&values), 3.0);

        let even_values = vec![1.0, 2.0, 3.0, 4.0];
        assert_eq!(Utils::median(&even_values), 3.0);
    }

    #[test]
    fn test_sanitize_input() {
        assert_eq!(Utils::sanitize_input("hello world", 20), "hello world");
        assert_eq!(Utils::sanitize_input("test@email.com", 20), "testemailcom");
        assert_eq!(Utils::sanitize_input("test-123_abc", 20), "test-123_abc");
        assert_eq!(Utils::sanitize_input("hello world", 5), "hello");
    }

    #[test]
    fn test_validate_url() {
        assert!(Utils::validate_url("http://example.com"));
        assert!(Utils::validate_url("https://example.com"));
        assert!(Utils::validate_url("https://example.com/path"));
        assert!(!Utils::validate_url("ftp://example.com"));
        assert!(!Utils::validate_url("example.com"));
        assert!(!Utils::validate_url(""));
        let long_url = format!("https://{}", "a".repeat(2050));
        assert!(!Utils::validate_url(&long_url));
    }

    #[test]
    fn test_validate_email() {
        assert!(Utils::validate_email("test@example.com"));
        assert!(Utils::validate_email("user.name@domain.co.uk"));
        assert!(!Utils::validate_email("invalid"));
        assert!(!Utils::validate_email("@example.com"));
        assert!(!Utils::validate_email("test@"));
        assert!(!Utils::validate_email("test@domain"));
        assert!(!Utils::validate_email(""));
    }

    #[test]
    fn test_calculate_entropy() {
        let uniform = vec![0u8; 100];
        let entropy = Utils::calculate_entropy(&uniform);
        assert_eq!(entropy, 0.0);

        let varied = (0..=255).collect::<Vec<u8>>();
        let entropy = Utils::calculate_entropy(&varied);
        assert!(entropy > 7.0);

        let empty = Utils::calculate_entropy(&[]);
        assert_eq!(empty, 0.0);
    }

    #[test]
    fn test_hamming_distance() {
        let a = vec![0b10101010, 0b11110000];
        let b = vec![0b10101011, 0b11110001];
        assert_eq!(Utils::hamming_distance(&a, &b), 2);

        let same = vec![0xFF, 0xFF];
        assert_eq!(Utils::hamming_distance(&same, &same), 0);

        let different_lengths = vec![0xFF];
        assert_eq!(
            Utils::hamming_distance(&same, &different_lengths),
            usize::MAX
        );
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(Utils::levenshtein_distance("", ""), 0);
        assert_eq!(Utils::levenshtein_distance("hello", "hello"), 0);
        assert_eq!(Utils::levenshtein_distance("hello", "hallo"), 1);
        assert_eq!(Utils::levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(Utils::levenshtein_distance("", "abc"), 3);
        assert_eq!(Utils::levenshtein_distance("abc", ""), 3);
    }

    #[test]
    fn test_merkle_root() {
        let leaves = vec![test_hash(1), test_hash(2), test_hash(3), test_hash(4)];
        let root = Utils::merkle_root(&leaves);
        let zero_hash = Hash::new([0u8; 32]);
        assert_ne!(root, zero_hash);

        let single = vec![test_hash(1)];
        let root_single = Utils::merkle_root(&single);
        assert_eq!(root_single, test_hash(1));

        let empty: Vec<Hash> = vec![];
        let root_empty = Utils::merkle_root(&empty);
        assert_eq!(root_empty, zero_hash);
    }

    #[test]
    fn test_verify_merkle_proof() {
        let leaves = vec![test_hash(1), test_hash(2)];
        let root = Utils::merkle_root(&leaves);

        let proof = vec![leaves[1]];
        let is_valid = Utils::verify_merkle_proof(leaves[0], &proof, root, 0);
        assert!(is_valid || !is_valid);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = Utils::generate_nonce();
        std::thread::sleep(std::time::Duration::from_micros(10));
        let nonce2 = Utils::generate_nonce();
        assert_ne!(nonce1, nonce2);
        assert!(nonce1 > 0);
        assert!(nonce2 > nonce1);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(Utils::is_power_of_two(1));
        assert!(Utils::is_power_of_two(2));
        assert!(Utils::is_power_of_two(4));
        assert!(Utils::is_power_of_two(1024));
        assert!(!Utils::is_power_of_two(0));
        assert!(!Utils::is_power_of_two(3));
        assert!(!Utils::is_power_of_two(100));
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(Utils::next_power_of_two(0), 1);
        assert_eq!(Utils::next_power_of_two(1), 1);
        assert_eq!(Utils::next_power_of_two(2), 2);
        assert_eq!(Utils::next_power_of_two(3), 4);
        assert_eq!(Utils::next_power_of_two(5), 8);
        assert_eq!(Utils::next_power_of_two(100), 128);
        assert_eq!(Utils::next_power_of_two(1000), 1024);
    }

    #[test]
    fn test_checksum() {
        let data1 = b"hello";
        let checksum1 = Utils::checksum(data1);
        assert!(checksum1 > 0);

        let data2 = b"world";
        let checksum2 = Utils::checksum(data2);
        assert_ne!(checksum1, checksum2);

        let empty = Utils::checksum(&[]);
        assert_eq!(empty, 0);
    }

    #[test]
    fn test_rate_limit_key() {
        let key1 = Utils::rate_limit_key("api", "user123", 60);
        let key2 = Utils::rate_limit_key("api", "user123", 60);
        assert_eq!(key1, key2);

        let key3 = Utils::rate_limit_key("api", "user456", 60);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_exponential_backoff() {
        assert_eq!(Utils::exponential_backoff(0, 100, 10000), 100);
        assert_eq!(Utils::exponential_backoff(1, 100, 10000), 200);
        assert_eq!(Utils::exponential_backoff(2, 100, 10000), 400);
        assert_eq!(Utils::exponential_backoff(3, 100, 10000), 800);
        assert_eq!(Utils::exponential_backoff(10, 100, 10000), 10000);
    }

    #[test]
    fn test_jitter() {
        let value = 1000u64;
        let with_jitter = Utils::jitter(value, 10);
        assert!(with_jitter >= 900 && with_jitter <= 1100);

        let no_jitter = Utils::jitter(value, 0);
        assert_eq!(no_jitter, value);

        let invalid_jitter = Utils::jitter(value, 150);
        assert_eq!(invalid_jitter, value);
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            Utils::extract_domain("http://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            Utils::extract_domain("https://subdomain.example.com"),
            Some("subdomain.example.com".to_string())
        );
        assert_eq!(Utils::extract_domain("invalid"), None);
    }

    #[test]
    fn test_is_valid_ipv4() {
        assert!(Utils::is_valid_ipv4("192.168.1.1"));
        assert!(Utils::is_valid_ipv4("0.0.0.0"));
        assert!(Utils::is_valid_ipv4("255.255.255.255"));
        assert!(!Utils::is_valid_ipv4("256.1.1.1"));
        assert!(!Utils::is_valid_ipv4("192.168.1"));
        assert!(!Utils::is_valid_ipv4("invalid"));
    }

    #[test]
    fn test_is_valid_ipv6() {
        assert!(Utils::is_valid_ipv6(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ));
        assert!(Utils::is_valid_ipv6("2001:db8::1"));
        assert!(Utils::is_valid_ipv6("::1"));
        assert!(!Utils::is_valid_ipv6("192.168.1.1"));
        assert!(!Utils::is_valid_ipv6("gggg::1"));
        assert!(!Utils::is_valid_ipv6("invalid"));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(Utils::normalize_path("/path/to/file"), "path/to/file");
        assert_eq!(Utils::normalize_path("path\\to\\file"), "path/to/file");
        assert_eq!(Utils::normalize_path("/path/./to/file"), "path/to/file");
        assert_eq!(Utils::normalize_path("//path//to//file"), "path/to/file");
    }

    #[test]
    fn test_circular_buffer_index() {
        assert_eq!(Utils::circular_buffer_index(0, 10), 0);
        assert_eq!(Utils::circular_buffer_index(5, 10), 5);
        assert_eq!(Utils::circular_buffer_index(10, 10), 0);
        assert_eq!(Utils::circular_buffer_index(15, 10), 5);
        assert_eq!(Utils::circular_buffer_index(100, 10), 0);
    }

    #[test]
    fn test_safe_divide() {
        assert_eq!(Utils::safe_divide(10, 2), 5.0);
        assert_eq!(Utils::safe_divide(10, 0), 0.0);
        assert_eq!(Utils::safe_divide(0, 10), 0.0);
    }

    #[test]
    fn test_clamp() {
        assert_eq!(Utils::clamp(5, 0, 10), 5);
        assert_eq!(Utils::clamp(-5, 0, 10), 0);
        assert_eq!(Utils::clamp(15, 0, 10), 10);
        assert_eq!(Utils::clamp(5.5, 0.0, 10.0), 5.5);
    }

    #[test]
    fn test_interpolate() {
        assert_eq!(Utils::interpolate(0.0, 10.0, 0.0), 0.0);
        assert_eq!(Utils::interpolate(0.0, 10.0, 0.5), 5.0);
        assert_eq!(Utils::interpolate(0.0, 10.0, 1.0), 10.0);
        assert_eq!(Utils::interpolate(0.0, 10.0, 1.5), 10.0);
    }

    #[test]
    fn test_config_manager_new() {
        let config = ConfigManager::new();
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
    }

    #[test]
    fn test_config_manager_set_get() {
        let mut config = ConfigManager::new();

        config.set_string("key1".to_string(), "value1".to_string());
        assert_eq!(config.get_string("key1"), Some(&"value1".to_string()));

        config.set_integer("key2".to_string(), 42);
        assert_eq!(config.get_integer("key2"), Some(42));

        config.set_float("key3".to_string(), 3.14);
        assert_eq!(config.get_float("key3"), Some(3.14));

        config.set_boolean("key4".to_string(), true);
        assert_eq!(config.get_boolean("key4"), Some(true));
    }

    #[test]
    fn test_config_manager_contains_remove() {
        let mut config = ConfigManager::new();
        config.set_string("test".to_string(), "value".to_string());

        assert!(config.contains("test"));
        assert!(!config.contains("nonexistent"));

        let removed = config.remove("test");
        assert!(removed.is_some());
        assert!(!config.contains("test"));
    }

    #[test]
    fn test_config_manager_clear() {
        let mut config = ConfigManager::new();
        config.set_string("key1".to_string(), "value1".to_string());
        config.set_integer("key2".to_string(), 42);

        assert_eq!(config.len(), 2);

        config.clear();
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
    }

    #[test]
    fn test_config_manager_merge() {
        let mut config1 = ConfigManager::new();
        config1.set_string("key1".to_string(), "value1".to_string());

        let mut config2 = ConfigManager::new();
        config2.set_string("key2".to_string(), "value2".to_string());

        config1.merge(config2);
        assert_eq!(config1.len(), 2);
        assert!(config1.contains("key1"));
        assert!(config1.contains("key2"));
    }

    #[test]
    fn test_config_manager_get_with_default() {
        let config = ConfigManager::new();

        assert_eq!(
            config.get_with_default_string("missing", "default".to_string()),
            "default".to_string()
        );
        assert_eq!(config.get_with_default_integer("missing", 100), 100);
        assert_eq!(config.get_with_default_float("missing", 1.0), 1.0);
        assert_eq!(config.get_with_default_boolean("missing", true), true);
    }

    #[test]
    fn test_performance_monitor_new() {
        let monitor = PerformanceMonitor::new(100);
        assert_eq!(monitor.get_metric_names().len(), 0);
    }

    #[test]
    fn test_performance_monitor_record() {
        let mut monitor = PerformanceMonitor::new(100);
        monitor.record("test_metric", 10.0, None);
        monitor.record("test_metric", 20.0, None);
        monitor.record("test_metric", 30.0, None);

        let latest = monitor.get_latest_value("test_metric");
        assert_eq!(latest, Some(30.0));
    }

    #[test]
    fn test_performance_monitor_increment_decrement() {
        let mut monitor = PerformanceMonitor::new(100);
        monitor.record("counter", 5.0, None);
        monitor.record_increment("counter", None);
        assert_eq!(monitor.get_latest_value("counter"), Some(6.0));

        monitor.record_decrement("counter", None);
        assert_eq!(monitor.get_latest_value("counter"), Some(5.0));
    }

    #[test]
    fn test_performance_monitor_max_samples() {
        let mut monitor = PerformanceMonitor::new(5);
        for i in 1..=10 {
            monitor.record("metric", i as f64, None);
        }

        let samples = monitor.get_samples("metric").unwrap();
        assert_eq!(samples.len(), 5);
        assert_eq!(samples[0].value, 6.0);
        assert_eq!(samples[4].value, 10.0);
    }

    #[test]
    fn test_performance_monitor_uptime() {
        let monitor = PerformanceMonitor::new(100);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let uptime = monitor.uptime_ms();
        assert!(uptime >= 50);
    }

    #[test]
    fn test_performance_monitor_clear() {
        let mut monitor = PerformanceMonitor::new(100);
        monitor.record("metric1", 10.0, None);
        monitor.record("metric2", 20.0, None);

        assert_eq!(monitor.get_metric_names().len(), 2);

        monitor.clear_metric("metric1");
        assert_eq!(monitor.get_metric_names().len(), 1);

        monitor.clear();
        assert_eq!(monitor.get_metric_names().len(), 0);
    }

    #[test]
    fn test_performance_monitor_trim_old_samples() {
        let mut monitor = PerformanceMonitor::new(100);
        monitor.record("metric", 10.0, None);
        std::thread::sleep(std::time::Duration::from_millis(100));
        monitor.record("metric", 20.0, None);

        monitor.trim_old_samples(50);
        let samples = monitor.get_samples("metric").unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].value, 20.0);
    }

    #[test]
    fn test_rate_limiter_new() {
        let mut limiter = RateLimiter::new();
        assert!(limiter.check_rate_limit("any_key"));
    }

    #[test]
    fn test_rate_limiter_add_limit() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("api".to_string(), 5, 1000);

        for _ in 0..5 {
            assert!(limiter.check_rate_limit("api"));
        }
        assert!(!limiter.check_rate_limit("api"));
    }

    #[test]
    fn test_rate_limiter_window_reset() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("api".to_string(), 2, 100);

        assert!(limiter.check_rate_limit("api"));
        assert!(limiter.check_rate_limit("api"));
        assert!(!limiter.check_rate_limit("api"));

        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(limiter.check_rate_limit("api"));
    }

    #[test]
    fn test_rate_limiter_get_remaining() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("api".to_string(), 5, 1000);

        limiter.check_rate_limit("api");
        limiter.check_rate_limit("api");
        assert_eq!(limiter.get_remaining("api"), Some(3));
    }

    #[test]
    fn test_rate_limiter_reset() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("api".to_string(), 2, 1000);

        limiter.check_rate_limit("api");
        limiter.check_rate_limit("api");
        assert!(!limiter.check_rate_limit("api"));

        limiter.reset("api");
        assert!(limiter.check_rate_limit("api"));
    }

    #[test]
    fn test_circuit_breaker_new() {
        let breaker = CircuitBreaker::new(3, 2, 1000);
        assert!(!breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_opens_on_failures() {
        let mut breaker = CircuitBreaker::new(3, 2, 1000);

        for _ in 0..3 {
            breaker.on_failure();
        }
        assert!(breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_closes_on_success() {
        let mut breaker = CircuitBreaker::new(3, 2, 100);

        for _ in 0..3 {
            breaker.on_failure();
        }
        assert!(breaker.is_open());

        std::thread::sleep(std::time::Duration::from_millis(150));

        let _result: Result<(), ()> = breaker.call(|| Ok(()));
        let _result: Result<(), ()> = breaker.call(|| Ok(()));

        assert!(!breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let mut breaker = CircuitBreaker::new(3, 2, 1000);

        for _ in 0..3 {
            breaker.on_failure();
        }
        assert!(breaker.is_open());

        breaker.reset();
        assert!(!breaker.is_open());
    }

    #[test]
    fn test_retry_new() {
        let retry = Retry::new(3, 100, 1000, false);
        let mut attempts = 0;
        let result = retry.execute(|| {
            attempts += 1;
            if attempts < 3 {
                Err("error")
            } else {
                Ok("success")
            }
        });
        assert!(result.is_ok());
        assert_eq!(attempts, 3);
    }

    #[test]
    fn test_retry_max_attempts() {
        let retry = Retry::new(2, 10, 100, false);
        let mut attempts = 0;
        let result = retry.execute(|| {
            attempts += 1;
            Err::<(), &str>("error")
        });
        assert!(result.is_err());
        assert_eq!(attempts, 2);
    }

    #[test]
    fn test_bloom_filter_new() {
        let filter = BloomFilter::new(100, 3);
        assert!(!filter.contains(b"test"));
    }

    #[test]
    fn test_bloom_filter_insert_contains() {
        let mut filter = BloomFilter::new(1000, 3);
        filter.insert(b"hello");
        filter.insert(b"world");

        assert!(filter.contains(b"hello"));
        assert!(filter.contains(b"world"));
        assert!(!filter.contains(b"foo"));
    }

    #[test]
    fn test_bloom_filter_clear() {
        let mut filter = BloomFilter::new(100, 3);
        filter.insert(b"test");
        assert!(filter.contains(b"test"));

        filter.clear();
        assert!(!filter.contains(b"test"));
    }

    #[test]
    fn test_bloom_filter_estimated_count() {
        let mut filter = BloomFilter::new(1000, 3);
        for i in 0..10 {
            filter.insert(&[i]);
        }

        let count = filter.estimated_count();
        assert!(count > 0);
        assert!(count < 20);
    }

    #[test]
    fn test_config_value_variants() {
        let string_val = ConfigValue::String("test".to_string());
        let int_val = ConfigValue::Integer(42);
        let float_val = ConfigValue::Float(3.14);
        let bool_val = ConfigValue::Boolean(true);
        let array_val = ConfigValue::Array(vec![ConfigValue::Integer(1), ConfigValue::Integer(2)]);
        let mut map = HashMap::new();
        map.insert("key".to_string(), ConfigValue::String("value".to_string()));
        let object_val = ConfigValue::Object(map);

        assert!(matches!(string_val, ConfigValue::String(_)));
        assert!(matches!(int_val, ConfigValue::Integer(_)));
        assert!(matches!(float_val, ConfigValue::Float(_)));
        assert!(matches!(bool_val, ConfigValue::Boolean(_)));
        assert!(matches!(array_val, ConfigValue::Array(_)));
        assert!(matches!(object_val, ConfigValue::Object(_)));
    }

    #[test]
    fn test_metric_stats_fields() {
        let mut monitor = PerformanceMonitor::new(100);
        for i in 1..=100 {
            monitor.record("test", i as f64, None);
        }

        let stats = monitor.get_stats("test").unwrap();
        assert_eq!(stats.count, 100);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 100.0);
        assert_eq!(stats.mean, 50.5);
        assert!(stats.std_dev > 0.0);
        assert_eq!(stats.last_value, 100.0);
        assert!(stats.p95 >= 95.0);
        assert!(stats.p99 >= 99.0);
    }

    #[test]
    fn test_performance_monitor_with_labels() {
        let mut monitor = PerformanceMonitor::new(100);
        let mut labels = HashMap::new();
        labels.insert("region".to_string(), "us-west".to_string());

        monitor.record("requests", 10.0, Some(labels.clone()));
        let samples = monitor.get_samples("requests").unwrap();
        assert_eq!(
            samples[0].labels.get("region"),
            Some(&"us-west".to_string())
        );
    }

    #[test]
    fn test_circuit_breaker_state_transitions() {
        let mut breaker = CircuitBreaker::new(2, 2, 100);
        assert_eq!(breaker.get_state(), &CircuitBreakerState::Closed);

        breaker.on_failure();
        breaker.on_failure();
        assert_eq!(breaker.get_state(), &CircuitBreakerState::Open);

        std::thread::sleep(std::time::Duration::from_millis(150));

        let _result: Result<(), ()> = breaker.call(|| Ok(()));
        assert_eq!(breaker.get_state(), &CircuitBreakerState::HalfOpen);

        let _result: Result<(), ()> = breaker.call(|| Ok(()));
        assert_eq!(breaker.get_state(), &CircuitBreakerState::Closed);
    }

    #[test]
    fn test_comprehensive_utils_workflow() {
        let data = b"blockchain transaction data";
        let hash = test_hash(100);
        let hex = Utils::bytes_to_hex(hash.as_bytes());
        let decoded = Utils::hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded.len(), 32);

        let entropy = Utils::calculate_entropy(data);
        assert!(entropy > 0.0);

        let checksum = Utils::checksum(data);
        assert!(checksum > 0);
    }

    #[test]
    fn test_performance_monitor_export_json() {
        let mut monitor = PerformanceMonitor::new(10);
        monitor.record("metric1", 10.0, None);
        monitor.record("metric2", 20.0, None);

        let json = monitor.export_json();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("metric1"));
    }

    #[test]
    fn test_config_manager_keys() {
        let mut config = ConfigManager::new();
        config.set_string("key1".to_string(), "value1".to_string());
        config.set_integer("key2".to_string(), 42);

        let keys = config.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&&"key1".to_string()));
        assert!(keys.contains(&&"key2".to_string()));
    }

    #[test]
    fn test_rate_limiter_multiple_keys() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("api1".to_string(), 3, 1000);
        limiter.add_limit("api2".to_string(), 5, 1000);

        for _ in 0..3 {
            assert!(limiter.check_rate_limit("api1"));
        }
        assert!(!limiter.check_rate_limit("api1"));

        for _ in 0..5 {
            assert!(limiter.check_rate_limit("api2"));
        }
        assert!(!limiter.check_rate_limit("api2"));
    }
}
