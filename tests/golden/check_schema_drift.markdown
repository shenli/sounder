## Sounder Evidence Packet

**Status:** Error
**Dataset:** `$TMP`
**Files scanned:** 3
**Rows:** 8
**Scan:** metadata_only (complete, data pages read: no)

### Findings

1. **Error - schema_drift**  
   schema variant 2b39741eaed128c0 appears in 1 files; baseline 37bce8bd99adc50f appears in 2 files

2. **Error - type_change**  
   column user_id changed from int64:None:def0 to byte_array:Some(String):def0 in 1 files


### Suggested next actions

- Compare against a previous healthy partition or dataset.
- Compare writer schema serialization for this column across affected files.
- Compare writer schemas for the affected files or partition.

