
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

# Locate the data folder
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

# Read the IPC schema
with open(DATA_DIR / "ipc_spec.json") as file:
    schema = json.load(file)

# Read the sample threat data
with open(DATA_DIR / "mock_threats.json") as file:
    processes = json.load(file)

# Check that the schema is valid
Draft202012Validator.check_schema(schema)

validator = Draft202012Validator(
    schema,
    format_checker=FormatChecker()
)

# Validate each process
for index, process in enumerate(processes, start=1):
    errors = list(validator.iter_errors(process))

    if not errors:
        print(f"Process {index}: PASS")
        print(f"  Name: {process['process_name']}")
    else:
        print(f"Process {index}: FAIL")
        for error in errors:
            print(f"  Error: {error.message}")
