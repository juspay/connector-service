# Xendit Connector Integration Logger

## Feedback Log

### Request/Response Structure Feedback
**Date**: [Current Date]

**Issue**: Request and Response structs do not match Hyperswitch reference exactly

**Details**:
- The `XenditPaymentsRequest` and `XenditPaymentsResponse` structs were not accurately implemented
- Several fields were either:
  - Missing from the original Hyperswitch implementation
  - Added incorrectly and not present in Hyperswitch
- Sub-structs and sub-enums also need to match Hyperswitch exactly

**Action Items**:
1. Review the Hyperswitch reference implementation at:
   - `https://github.com/juspay/hyperswitch/blob/main/crates/hyperswitch_connectors/src/connectors/xendit/transformers.rs`
2. Update the following structs to match Hyperswitch exactly:
   - `XenditPaymentsRequest`
   - `XenditPaymentsResponse`
   - All related sub-structs and enums
3. Remove any fields that don't exist in Hyperswitch
4. Add any missing fields from Hyperswitch

**Status**: Pending Fix

**Next Steps**:
1. Compare current implementation with Hyperswitch reference
2. Make necessary corrections to match Hyperswitch exactly
3. Test the updated implementation
4. Document any differences found between current implementation and Hyperswitch 