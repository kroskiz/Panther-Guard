import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.process_evidence import collect_file_evidence


class TestProcessEvidence(unittest.TestCase):
    def test_hashes_and_checks_only_previously_flagged_files(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "sample.exe"
            file_path.write_bytes(b"sample executable bytes")
            key = os.path.normcase(os.path.normpath(str(file_path)))
            records = [
                {
                    "executable_path": str(file_path),
                    "preliminary_threat_level": "medium",
                },
                {
                    "executable_path": None,
                    "preliminary_threat_level": "low",
                },
            ]
            signature_result = {
                key: {"signature_status": "NotSigned", "signer": None}
            }

            with patch(
                "src.process_evidence._inspect_signatures",
                return_value=(signature_result, []),
            ) as inspect_signatures:
                warnings = collect_file_evidence(records)

            inspect_signatures.assert_called_once_with([str(file_path)])
            self.assertEqual(records[0]["file_hash_status"], "available")
            self.assertEqual(
                records[0]["file_sha256"],
                hashlib.sha256(b"sample executable bytes").hexdigest(),
            )
            self.assertEqual(records[0]["signature_status"], "NotSigned")
            self.assertEqual(records[1]["signature_status"], "not_checked")
            self.assertFalse(warnings)


if __name__ == "__main__":
    unittest.main()
