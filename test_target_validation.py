import unittest

from target_validation import validate_target


class TargetValidationTests(unittest.TestCase):

    def test_valid_ipv4_is_accepted(self):
        result = validate_target("192.168.1.10")

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "ipv4")
        self.assertEqual(result.normalized_target, "192.168.1.10")

    def test_invalid_ipv4_is_rejected(self):
        result = validate_target("192.168.1.999")

        self.assertFalse(result.valid)
        self.assertEqual(result.error, "Invalid IPv4 address.")

    def test_valid_hostname_is_accepted(self):
        result = validate_target("scanner.example.com")

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "hostname")
        self.assertEqual(result.normalized_target, "scanner.example.com")

    def test_invalid_hostname_is_rejected(self):
        result = validate_target("bad_host!.example.com")

        self.assertFalse(result.valid)
        self.assertEqual(result.error, "Invalid or unsupported hostname.")

    def test_empty_target_is_rejected(self):
        result = validate_target("   ")

        self.assertFalse(result.valid)
        self.assertEqual(result.error, "Target cannot be empty.")

    def test_hostname_is_normalized(self):
        result = validate_target("Scanner.Example.COM")

        self.assertTrue(result.valid)
        self.assertEqual(result.normalized_target, "scanner.example.com")


if __name__ == "__main__":
    unittest.main()