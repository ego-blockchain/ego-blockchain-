/// Rebuilding local peer discovery after the network underneath it changes.
///
/// libp2p's mDNS binds a socket to each interface address it is told about, and joins the
/// multicast group on it. When the WiFi drops and comes back the address it was given is
/// gone by the time it binds, and the bind fails with "the requested address is not valid
/// in its context". libp2p logs that and moves on: the interface is never retried, because
/// it only builds one when its watcher reports an address coming up, and that address
/// already did. Local discovery is then dead until the app restarts.
///
/// Nothing about that is visible as an event, so it cannot be caught and retried. What can
/// be seen is the address this machine now has. When it changes, discovery is rebuilt from
/// scratch, which re-enumerates the interfaces that exist now rather than the ones that
/// existed then.
pub const REBUILD_ATTEMPTS: u8 = 3;

pub struct Watch {
    seen: String,
    pending: u8,
}

impl Watch {
    pub fn starting_at(ip: &str) -> Self {
        Watch { seen: ip.to_string(), pending: 0 }
    }

    pub fn seen(&self) -> &str {
        &self.seen
    }

    /// Whether discovery should be rebuilt on this tick.
    ///
    /// A changed address schedules several attempts rather than one: an address can be
    /// assigned a moment before the interface will accept a multicast join, and a single
    /// try at exactly the wrong moment fails the same way the original did.
    pub fn tick(&mut self, current_ip: &str) -> bool {
        if current_ip != self.seen {
            self.seen = current_ip.to_string();
            self.pending = REBUILD_ATTEMPTS;
        }
        if self.pending > 0 {
            self.pending -= 1;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_settled_network_rebuilds_nothing() {
        let mut w = Watch::starting_at("192.168.1.20");
        for _ in 0..20 {
            assert!(!w.tick("192.168.1.20"));
        }
    }

    #[test]
    fn a_new_address_rebuilds_more_than_once() {
        let mut w = Watch::starting_at("192.168.1.20");
        let mut rebuilds = 0;
        for _ in 0..10 {
            if w.tick("10.0.0.5") {
                rebuilds += 1;
            }
        }
        assert_eq!(
            rebuilds, REBUILD_ATTEMPTS as usize,
            "one attempt can land before the interface will accept a multicast join",
        );
    }

    #[test]
    fn moving_back_to_the_old_network_counts_as_a_change() {
        let mut w = Watch::starting_at("192.168.1.20");
        for _ in 0..10 {
            w.tick("10.0.0.5");
        }
        assert!(w.tick("192.168.1.20"), "the old address is not the one discovery is bound to now");
    }

    #[test]
    fn losing_the_network_and_getting_it_back_rebuilds_on_the_way_back() {
        let mut w = Watch::starting_at("192.168.1.20");
        assert!(w.tick("127.0.0.1"), "the link went down");
        for _ in 0..10 {
            w.tick("127.0.0.1");
        }
        assert!(w.tick("192.168.1.31"), "a different lease on the way back is still a change");
        assert_eq!(w.seen(), "192.168.1.31");
    }
}
