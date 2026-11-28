import unittest

from src.security_rules import assess_process


class TestSecurityRules(unittest.TestCase):
    def test_normal_process_has_no_configured_indicators(self):
        level, reasons = assess_process(
            {
                "process_name": "example.exe",
                "executable_path": r"C:\Program Files\Example\example.exe",
                "parent_process_name": "explorer.exe",
            }
        )

        self.assertEqual(level, "low")
        self.assertIn("No configured suspicious indicators observed; not proof of safety", reasons)

    def test_user_writable_executable_is_warning(self):
        level, reasons = assess_process(
            {
                "process_name": "example.exe",
                "executable_path": r"C:\Users\Alice\AppData\Local\Temp\example.exe",
            }
        )

        self.assertEqual(level, "medium")
        self.assertIn("Executable is running from a user-writable location", reasons)

    def test_office_parent_starting_script_process_is_warning(self):
        level, reasons = assess_process(
            {
                "process_name": "powershell.exe",
                "executable_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "parent_process_name": "WINWORD.EXE",
            }
        )

        self.assertEqual(level, "medium")
        self.assertIn("winword.exe started a scripting or command interpreter", reasons)

    def test_combined_user_writable_path_and_encoded_command_is_critical(self):
        level, reasons = assess_process(
            {
                "process_name": "powershell.exe",
                "executable_path": r"C:\Users\Alice\Downloads\powershell.exe",
                "command_line_indicators": ["encoded_powershell_command"],
            }
        )

        self.assertEqual(level, "high")
        self.assertEqual(len(reasons), 2)

    def test_windows_system_process_name_outside_system_directory_is_critical(self):
        level, reasons = assess_process(
            {
                "process_name": "svchost.exe",
                "executable_path": r"C:\Users\Alice\svchost.exe",
            }
        )

        self.assertEqual(level, "high")
        self.assertEqual(len(reasons), 1)

    def test_name_alone_does_not_change_severity(self):
        level, _ = assess_process(
            {
                "process_name": "malware.exe",
                "executable_path": r"C:\Program Files\Example\malware.exe",
            }
        )

        self.assertEqual(level, "low")

    def test_unsigned_file_adds_a_review_signal(self):
        level, reasons = assess_process(
            {
                "process_name": "example.exe",
                "executable_path": r"C:\Program Files\Example\example.exe",
                "signature_status": "NotSigned",
            }
        )

        self.assertEqual(level, "medium")
        self.assertIn("Executable does not have a digital signature", reasons)

    def test_signature_mismatch_combined_with_user_writable_path_is_high(self):
        level, reasons = assess_process(
            {
                "process_name": "example.exe",
                "executable_path": r"C:\Users\Alice\Downloads\example.exe",
                "signature_status": "HashMismatch",
            }
        )

        self.assertEqual(level, "high")
        self.assertIn("Executable does not match its digital signature", reasons)


if __name__ == "__main__":
    unittest.main()
