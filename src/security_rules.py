# These names matter only when their executable path is unexpected.
CORE_WINDOWS_PROCESSES = {
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "spoolsv.exe",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
}

OFFICE_PROCESSES = {
    "excel.exe",
    "msaccess.exe",
    "onenote.exe",
    "outlook.exe",
    "powerpnt.exe",
    "winword.exe",
}

SCRIPT_PROCESSES = {
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "rundll32.exe",
    "wscript.exe",
}

COMMAND_LINE_REASONS = {
    "encoded_powershell_command": "PowerShell was started with an encoded command",
    "hidden_powershell_window": "PowerShell was started with a hidden window",
    "powershell_execution_policy_bypass": "PowerShell was started with execution-policy bypass",
}


def _is_user_writable_path(executable_path: str) -> bool:
    # Normalize Windows path separators and case before checking known writable locations.
    normalized = executable_path.replace("/", "\\").casefold()
    return any(
        marker in normalized
        for marker in (
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\downloads\\",
            "\\users\\public\\",
            "\\windows\\temp\\",
        )
    )


def _is_windows_system_directory(executable_path: str) -> bool:
    normalized = executable_path.replace("/", "\\").casefold()
    return "\\windows\\system32\\" in normalized or "\\windows\\syswow64\\" in normalized


def assess_process(record: dict) -> tuple[str, list[str]]:
    """Return a cautious heuristic severity and the observable reasons behind it."""
    # Add independent signals; a process name by itself does not increase the score.
    score = 0
    reasons = []
    process_name = str(record.get("process_name", "")).casefold()
    executable_path = record.get("executable_path")
    parent_name = str(record.get("parent_process_name") or "").casefold()
    command_line_indicators = set(record.get("command_line_indicators") or [])

    if executable_path:
        if _is_user_writable_path(executable_path):
            score += 1
            reasons.append("Executable is running from a user-writable location")

        if (
            process_name in CORE_WINDOWS_PROCESSES
            and not _is_windows_system_directory(executable_path)
        ):
            score += 3
            reasons.append("Windows system-process name is running outside a Windows system directory")
    else:
        reasons.append("Executable path is unavailable; path-based checks were skipped")

    if parent_name in OFFICE_PROCESSES and process_name in SCRIPT_PROCESSES:
        score += 2
        reasons.append(f"{parent_name} started a scripting or command interpreter")

    matched_command_indicators = sorted(command_line_indicators & COMMAND_LINE_REASONS.keys())
    if matched_command_indicators:
        score += 2
        reasons.extend(COMMAND_LINE_REASONS[indicator] for indicator in matched_command_indicators)

    signature_status = str(record.get("signature_status") or "").casefold()
    if signature_status == "notsigned":
        score += 1
        reasons.append("Executable does not have a digital signature")
    elif signature_status == "hashmismatch":
        score += 2
        reasons.append("Executable does not match its digital signature")
    elif signature_status == "nottrusted":
        score += 1
        reasons.append("Executable signature is not trusted by this system")

    # One or two points are Medium; three or more are High.
    if score >= 3:
        return "high", reasons
    if score >= 1:
        return "medium", reasons

    # Low means no configured indicators were observed, not that the process is verified safe.
    return "low", reasons or ["No configured suspicious indicators observed; not proof of safety"]
