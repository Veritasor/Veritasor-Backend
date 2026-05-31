use super::*;
use std::panic::catch_unwind;
use proptest::prelude::*;

// We use proptest to assert monotonicity across all combinations of inputs.
proptest! {
    #[test]
    fn test_extend_expiry_properties(
        timestamp in any::<u64>(),
        old_expiry in any::<u64>(),
        new_expiry in any::<u64>()
    ) {
        // Setup initial contract state
        let mut contract = Contract::new(old_expiry);

        // We catch un-winding (panics) since the function is expected to panic on invalid inputs
        let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.extend_expiry(timestamp, new_expiry);
        }));

        // Assert panics for all non-monotonic cases
        if new_expiry <= old_expiry || new_expiry <= timestamp {
            // Invariant: Non-monotonic cases must panic
            assert!(result.is_err(), "Expected panic when new_expiry is not strictly greater than old_expiry and timestamp");
            
            // Invariant: On panic, the storage should not be mutated
            assert_eq!(contract.current_expiry, old_expiry, "Storage should not mutate on panic");
            assert!(contract.events.is_empty(), "No events should be emitted on panic");
        } else {
            // Assert success for strictly greater values
            assert!(result.is_ok(), "Expected success for monotonic case");

            // Invariant: Storage reflects the new applied value
            assert_eq!(contract.current_expiry, new_expiry, "Storage should be updated to new_expiry");

            // Invariant: Emitted event payload exactly matches the stored value
            assert_eq!(contract.events.len(), 1, "Exactly one event should be emitted on success");
            assert_eq!(contract.events[0].new_expiry, new_expiry, "Event payload must match the new_expiry");
        }
    }

    #[test]
    fn test_extend_expiry_random_sequences(
        timestamp in any::<u64>(),
        initial_expiry in any::<u64>(),
        // Generate a sequence of random extension deltas to ensure we strictly increase
        deltas in proptest::collection::vec(1..1000_u64, 1..20)
    ) {
        let mut contract = Contract::new(initial_expiry);
        let mut current = initial_expiry;
        
        // Ensure timestamp is initially below the initial_expiry for validity in this sequence test,
        // or just manage timestamp to be always below `current`
        let mut ts = timestamp.min(initial_expiry.saturating_sub(1));

        for delta in deltas {
            // Calculate strictly monotonic new_expiry
            let new_expiry = current.saturating_add(delta);
            
            // In the event of saturation where new_expiry == current, it will naturally panic, 
            // which aligns with our rule that new_expiry > current_expiry
            let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
                contract.extend_expiry(ts, new_expiry);
            }));

            if new_expiry > current && new_expiry > ts {
                assert!(result.is_ok());
                assert_eq!(contract.current_expiry, new_expiry);
                assert_eq!(contract.events.last().unwrap().new_expiry, new_expiry);
                current = new_expiry;
            } else {
                assert!(result.is_err());
            }
            
            // Advance timestamp slightly, ensuring it doesn't surpass current for the next step
            ts = ts.saturating_add(1).min(current.saturating_sub(1));
        }
        
        // Invariant: Storage always reflects the maximum applied value across the sequence
        assert_eq!(contract.current_expiry, current, "Storage should reflect the max valid applied value");
    }
}

#[test]
fn test_extend_expiry_edge_cases() {
    // Edge case: new_expiry == old_expiry
    let mut contract = Contract::new(100);
    let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.extend_expiry(50, 100);
    }));
    assert!(result.is_err(), "Must panic when new_expiry == old_expiry");

    // Edge case: new_expiry == timestamp
    let mut contract = Contract::new(100);
    let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.extend_expiry(150, 150);
    }));
    assert!(result.is_err(), "Must panic when new_expiry == timestamp");

    // Edge case: u64::MAX saturating cases
    // Valid case at the maximum boundary
    let mut contract = Contract::new(u64::MAX - 1);
    let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.extend_expiry(u64::MAX - 2, u64::MAX);
    }));
    assert!(result.is_ok(), "Must succeed up to u64::MAX");
    assert_eq!(contract.current_expiry, u64::MAX);

    // Attempting to extend beyond u64::MAX or staying at u64::MAX
    let mut contract = Contract::new(u64::MAX);
    let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
        contract.extend_expiry(u64::MAX - 1, u64::MAX);
    }));
    assert!(result.is_err(), "Must panic when new_expiry == old_expiry at u64::MAX");
}
