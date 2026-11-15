//! When a starting guest's boot stages reached the host (#4242).

use codewire_vmm_guest_probe::GuestBootStage;

/// When the host first received each guest boot stage, and when the guest
/// was ready for the network, for the runner log (#4242). These are receive
/// times: a stage the guest reached while the progress port was not yet
/// served arrives with the first frame after it.
#[derive(Debug, Default)]
pub(crate) struct GuestStageTimes {
    seen: Vec<(GuestBootStage, std::time::Instant)>,
    guest_ready: Option<std::time::Instant>,
}

impl GuestStageTimes {
    pub(crate) fn record(&mut self, stage: GuestBootStage) {
        if !self.seen.iter().any(|(seen, _)| *seen == stage) {
            self.seen.push((stage, std::time::Instant::now()));
        }
    }

    pub(crate) fn seen(&self) -> &[(GuestBootStage, std::time::Instant)] {
        &self.seen
    }

    /// When the guest reported the root generation ready, which ends the
    /// guest's half of the network wait.
    pub(crate) fn guest_ready(&self) -> Option<std::time::Instant> {
        self.guest_ready
    }

    pub(crate) fn mark_guest_ready(&mut self) {
        self.guest_ready = Some(std::time::Instant::now());
    }
}
