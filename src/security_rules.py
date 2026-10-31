
# PantherGuard - Basic Security Classification Rules

# Example names for testing, not reliable malware indicators
WARNING_PROCESSES = {"unknown_process.exe", "suspicious.exe"}
CRITICAL_PROCESSES = {"malware.exe", "ransomware.exe"}

def classify_process(process_name):
    name = process_name.strip().lower()

    if name in CRITICAL_PROCESSES:
        return "high"
    elif name in WARNING_PROCESSES:
        return "medium"
    else:
        return "low"


# Test our classification rules
if __name__ == "__main__":
    test_processes = [
        "chrome.exe",
        "unknown_process.exe",
        "malware.exe"
    ]

    for process in test_processes:
        level = classify_process(process)
        print(f"{process}: {level}")
