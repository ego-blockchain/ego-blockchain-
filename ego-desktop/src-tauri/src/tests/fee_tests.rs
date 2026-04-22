#[cfg(test)]
mod fee_tests {
    use crate::chain_db::compute_next_base_fee;

    #[test]
    fn fee_increases_above_target() {
        assert!(compute_next_base_fee(1_000, 10_000) > 1_000);
    }
    #[test]
    fn fee_decreases_below_target() {
        assert!(compute_next_base_fee(10_000, 0) < 10_000);
    }
    #[test]
    fn fee_floor_enforced() {
        assert!(compute_next_base_fee(1_000, 0) >= 1_000);
    }
    #[test]
    fn fee_stable_at_target() {
        assert_eq!(compute_next_base_fee(5_000, 5_000), 5_000);
    }
}
