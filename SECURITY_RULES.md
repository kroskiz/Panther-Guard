
# PantherGuard Security Rules

## Purpose
Define how PantherGuard classifies process activity into three threat levels.

## Threat Level Checklist

### Low
- No configured indicators were found.
- This is not a verification that the process is safe.

### Medium
- One configured review signal was found.
- Review the listed evidence and process context.

### High
- Multiple signals combine to meet the high threshold, or a strong system-process name/path mismatch is present.
- This is still a heuristic priority, not a confirmed malicious detection.

## Current Implementation

The scanner assigns heuristic review levels using observable process metadata. A process name alone does not determine its level.

- **Low:** no configured indicator was found. This is not proof the process is safe.
- **Medium:** one review signal, such as execution from a user-writable location, an Office application launching a script/command interpreter, or selected risky PowerShell command-line options.
- **High:** combined signals reach the high threshold, or a Windows core-process name is running outside a Windows system directory.

The current scoring uses:
- 1 point for an executable under common user-writable locations (Temp, Roaming, Downloads, or Public).
- 2 points for Office spawning a script/command interpreter.
- 2 points for selected PowerShell options (encoded command, hidden window, or execution-policy bypass).
- 3 points for a Windows core-process name outside System32/SysWOW64.
- 1 point when an inspected executable is unsigned or its signature is not trusted.
- 2 points when an inspected executable does not match its digital signature.

Scores of 0 are Low, 1–2 are Medium, and 3 or more are High. Reasons are included with each record. These are triage heuristics, not confirmed detections. For processes already flagged by another heuristic, Panther Guard checks the local Authenticode status and computes a SHA-256 hash. An unsigned, untrusted, or signature-mismatched file adds evidence; a valid signature does not prove a file is safe. Hashes are displayed for manual review only—there is no threat-intelligence lookup.

## IPC Compatibility

The classification function returns:
- low = no configured indicators found (not verified safe)
- medium = warning / review
- high = critical review priority

These values match data/ipc_spec.json.

The process snapshot `status` field is separate from threat level:
- `New` means the PID/start-time pair was not present in the previous successful snapshot (or this is the first snapshot).
- `Previously Seen` means that process instance was present in the previous successful snapshot. Start time helps distinguish a new process that reused an old PID.

These labels describe observation history only; they do not establish whether a process is safe or malicious. A process that starts and exits between scans may not be observed, and a reused PID may appear previously seen.

The scanner checks signatures and computes hashes only after another heuristic flags a process. It does not query a trusted hash-reputation source. Command-line contents are not stored or displayed; only the selected PowerShell indicator names are emitted.

## The Future Improvements

- Compare hashes against an approved, trusted threat-intelligence source.
- Add event-based monitoring so short-lived processes and behavior between snapshots can be reviewed.
- Review heuristic rules against expected organizational software to reduce false positives.
