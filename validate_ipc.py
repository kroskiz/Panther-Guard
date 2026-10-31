
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

# Locate the project folders
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

# Load the IPC schema
with open(DATA_DIR / "ipc_spec.json") as file:
    schema = json.load(file)

# Choose which JSON file to validate
if len(sys.argv) > 1:
    json_file = Path(sys.argv[1])
else:
    json_file = DATA_DIR / "mock_threats.json"

# Read the JSON data
try:
    with open(json_file) as file:
        processes = json.load(file)
except (OSError, json.JSONDecodeError) as error:
    print(f"Error reading JSON file: {error}")
    sys.exit(1)

# Check that the schema is valid
Draft202012Validator.check_schema(schema)

validator = Draft202012Validator(
    schema,
    format_checker=FormatChecker()
)

# Accept a single process or a list of processes
if isinstance(processes, dict):
    processes = [processes]
elif not isinstance(processes, list):
    print("FAIL: JSON must contain a process object or a list of processes.")
    sys.exit(1)

# Validate each process
failed = False

for index, process in enumerate(processes, start=1):
    errors = list(validator.iter_errors(process))

    if not errors:
        print(f"Process {index}: PASS")
        print(f"  Name: {process['process_name']}")
    else:
        failed = True
        print(f"Process {index}: FAIL")
        for error in errors:
            print(f"  Error: {error.message}")

# Report the final result
if failed:
    print("Validation failed.")
    sys.exit(1)
else:
    print("All processes passed validation.")
