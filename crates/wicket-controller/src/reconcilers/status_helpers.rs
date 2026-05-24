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

#[cfg(test)]
mod tests {
    use super::*;

    fn condition(
        type_: &str,
        status: &str,
        reason: &str,
        message: &str,
        observed_generation: Option<i64>,
        last_transition_time: &str,
    ) -> Condition {
        Condition {
            type_: type_.to_string(),
            status: status.to_string(),
            observed_generation,
            last_transition_time: last_transition_time.to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn conditions_semantically_equal_ignores_last_transition_time() {
        let a = [condition(
            "Accepted",
            "True",
            "Accepted",
            "Resource has been accepted",
            Some(7),
            "2024-01-01T00:00:00Z",
        )];
        let b = [condition(
            "Accepted",
            "True",
            "Accepted",
            "Resource has been accepted",
            Some(7),
            "2024-01-02T00:00:00Z",
        )];

        assert!(conditions_semantically_equal(&a, &b));
    }

    #[test]
    fn conditions_semantically_equal_detects_real_changes() {
        let base = condition(
            "Accepted",
            "True",
            "Accepted",
            "Resource has been accepted",
            Some(7),
            "2024-01-01T00:00:00Z",
        );

        for changed in [
            condition(
                "Accepted",
                "False",
                "Accepted",
                "Resource has been accepted",
                Some(7),
                "2024-01-02T00:00:00Z",
            ),
            condition(
                "Accepted",
                "True",
                "Rejected",
                "Resource has been accepted",
                Some(7),
                "2024-01-02T00:00:00Z",
            ),
            condition(
                "Accepted",
                "True",
                "Accepted",
                "Something else",
                Some(7),
                "2024-01-02T00:00:00Z",
            ),
            condition(
                "Accepted",
                "True",
                "Accepted",
                "Resource has been accepted",
                Some(8),
                "2024-01-02T00:00:00Z",
            ),
        ] {
            assert!(!conditions_semantically_equal(
                std::slice::from_ref(&base),
                &[changed]
            ));
        }
    }

    #[test]
    fn preserve_condition_timestamps_keeps_matching_statuses_stable() {
        let existing = [
            condition(
                "Accepted",
                "True",
                "Accepted",
                "Resource has been accepted",
                Some(7),
                "2024-01-01T00:00:00Z",
            ),
            condition(
                "Programmed",
                "False",
                "DeploymentNotReady",
                "Managed runtime Deployment rollout has not converged",
                Some(7),
                "2024-01-01T01:00:00Z",
            ),
        ];
        let mut new = vec![
            condition(
                "Accepted",
                "True",
                "Accepted",
                "Resource has been accepted",
                Some(7),
                "2024-02-01T00:00:00Z",
            ),
            condition(
                "Programmed",
                "True",
                "Programmed",
                "Resource has been programmed",
                Some(7),
                "2024-02-01T01:00:00Z",
            ),
        ];

        preserve_condition_timestamps(&mut new, &existing);

        assert_eq!(
            new[0].last_transition_time,
            existing[0].last_transition_time
        );
        assert_eq!(new[1].last_transition_time, "2024-02-01T01:00:00Z");
    }
}
