use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

/// Request-scoped accumulator for time spent in outbound connector calls.
///
/// The inner counter is atomic so the same request context can be cloned into
/// concurrent connector work without locks.
#[derive(Clone, Debug, Default)]
pub struct ConnectorLatencyTracker {
    nanos: Arc<AtomicU64>,
    outgoing_millis: Arc<AtomicU64>,
}

impl ConnectorLatencyTracker {
    pub fn add_connector_time(&self, elapsed: Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    pub fn connector_time(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::Relaxed))
    }

    /// Add the exact millisecond value emitted on an outgoing golden log line.
    pub fn add_outgoing_latency_millis(&self, elapsed_millis: u64) {
        // The closure always returns `Some`, so the update cannot fail.
        let _ =
            self.outgoing_millis
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(elapsed_millis))
                });
    }

    /// Sum of the `latency_ms` values emitted by outgoing calls in this request.
    pub fn outgoing_latency_millis(&self) -> u64 {
        self.outgoing_millis.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectorLatencyTracker;

    #[test]
    fn cloned_trackers_sum_exact_outgoing_log_latencies() {
        let tracker = ConnectorLatencyTracker::default();
        let cloned_tracker = tracker.clone();

        tracker.add_outgoing_latency_millis(1875);
        cloned_tracker.add_outgoing_latency_millis(1974);

        assert_eq!(tracker.outgoing_latency_millis(), 3849);
    }

    #[test]
    fn outgoing_log_latency_saturates_instead_of_wrapping() {
        let tracker = ConnectorLatencyTracker::default();

        tracker.add_outgoing_latency_millis(u64::MAX);
        tracker.add_outgoing_latency_millis(1);

        assert_eq!(tracker.outgoing_latency_millis(), u64::MAX);
    }
}
