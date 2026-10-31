
# PantherGuard Security Rules

## Purpose
Define how PantherGuard classifies process activity into three threat levels.

## Threat Level Checklist

### Safe (low)
- [ ] No suspicious indicators detected
- [ ] No known malicious behavior observed
- [ ] No security alerts triggered

### Warning (medium)
- [ ] Process displays potentially suspicious behavior
- [ ] Process requires further investigation
- [ ] Unusual execution activity detected

### Critical (high)
- [ ] Strong indicators of malicious behavior
- [ ] Known malicious activity confirmed
- [ ] Immediate security investigation recommended

## Current Implementation

The current Python prototype uses example process-name lists:

- chrome.exe: low
- unknown_process.exe: medium
- malware.exe: high

These classifications are for testing only. Process names alone cannot establish whether software is safe or malicious.

## IPC Compatibility

The classification function returns:
- low = Safe
- medium = Warning
- high = Critical

These values match data/ipc_spec.json.

## The Future Improvements

- Analyze process execution paths
- Detect unusual parent-child process relationships
- Check trusted threat intelligence sources
- Integrate real process monitoring data
