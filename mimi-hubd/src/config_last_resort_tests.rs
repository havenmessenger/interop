//! `MIMI_LAST_RESORT_REUSE`: off unless set to `true`, and a value that is neither stops the start.

use super::last_resort_reuse;

/// Unset and `false` are off, `true` is on, and anything else is refused rather than read as either. Revert check: read
/// any other value as off, and a mistyped `ture` starts the hub.
#[test]
fn reuse_is_off_unless_set_to_true_and_other_values_are_refused() {
    assert!(!last_resort_reuse(None).unwrap());
    assert!(!last_resort_reuse(Some("false")).unwrap());
    assert!(last_resort_reuse(Some("true")).unwrap());
    for typo in ["ture", "1", "yes", "TRUE", ""] {
        assert!(
            last_resort_reuse(Some(typo)).is_err(),
            "PLANT-CONFIG-LAST-RESORT: {typo:?} was taken as a setting"
        );
    }
}
