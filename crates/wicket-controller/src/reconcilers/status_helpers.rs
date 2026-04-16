//! Shared helpers for status patch idempotency.
//!
//! All reconcilers that patch `.status.conditions` on Gateway API resources
//! hit the same class of bug: a fresh `last_transition_time` on every
//! reconcile causes the object to mutate, which triggers a watch event,
//! which re-reconciles — an infinite loop.
//!
//! These helpers provide:
//! 1. Semantic equality — compares conditions ignoring `last_transition_time`
//! 2. Timestamp preservation — copies existing timestamps onto new conditions
//!    when the logical status hasn't changed

use crate::crds::Condition;

/// Returns true when two condition slices describe the same logical state,
/// ignoring `last_transition_time`.
pub fn conditions_semantically_equal(a: &[Condition], b: &[Condition]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(x, y)| {
        x.type_ == y.type_
            && x.status == y.status
            && x.reason == y.reason
            && x.message == y.message
            && x.observed_generation == y.observed_generation
    })
}

/// Copy `last_transition_time` from existing conditions onto new conditions
/// where the logical status (type + status) hasn't changed.  This makes the
/// subsequent status patch idempotent: if nothing actually changed, the
/// serialized status will be byte-for-byte identical and the patch becomes
/// a no-op at the API server level.
pub fn preserve_condition_timestamps(new: &mut [Condition], existing: &[Condition]) {
    for cond in new.iter_mut() {
        if let Some(prev) = existing.iter().find(|e| e.type_ == cond.type_) {
            if prev.status == cond.status {
                cond.last_transition_time = prev.last_transition_time.clone();
            }
        }
    }
}
