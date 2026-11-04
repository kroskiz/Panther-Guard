
import unittest
from src.security_rules import classify_process


class TestSecurityRules(unittest.TestCase):

    def test_safe_process(self):
        self.assertEqual(classify_process("chrome.exe"), "low")

    def test_warning_process(self):
        self.assertEqual(
            classify_process("unknown_process.exe"),
            "medium"
        )

    def test_critical_process(self):
        self.assertEqual(
            classify_process("malware.exe"),
            "high"
        )

    def test_case_insensitive(self):
        self.assertEqual(
            classify_process("MALWARE.EXE"),
            "high"
        )


if __name__ == "__main__":
    unittest.main()
