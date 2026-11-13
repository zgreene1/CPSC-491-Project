

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

    def test_ipv4_with_leading_and_trailing_spaces_is_normalized(self):
        result = validate_target("  192.168.1.10  ")

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "ipv4")
        self.assertEqual(result.normalized_target, "192.168.1.10")

    def test_hostname_with_leading_and_trailing_spaces_is_normalized(self):
        result = validate_target("  Scanner.Example.COM  ")

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "hostname")
        self.assertEqual(result.normalized_target, "scanner.example.com")

    def test_hostname_with_double_dot_is_rejected(self):
        result = validate_target("scanner..example.com")

        self.assertFalse(result.valid)
        self.assertEqual(result.error, "Invalid or unsupported hostname.")

    def test_ipv4_with_too_few_octets_is_rejected(self):
        result = validate_target("192.168.1")

        self.assertFalse(result.valid)

    # SCRUM-71: Additional hostname boundary and negative tests

    def test_hostname_63_character_label_is_accepted(self):
        hostname = "a" * 63 + ".example.com"
        result = validate_target(hostname)

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "hostname")
        self.assertEqual(result.normalized_target, hostname)

    def test_hostname_64_character_label_is_rejected(self):
        hostname = "a" * 64 + ".example.com"
        result = validate_target(hostname)

        self.assertFalse(result.valid)
        self.assertEqual(result.error, "Invalid or unsupported hostname.")

    def test_hostname_trailing_dot_is_normalized(self):
        result = validate_target("Scanner.Example.COM.")

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "hostname")
        self.assertEqual(result.normalized_target, "scanner.example.com")

    def test_hostname_over_253_characters_is_rejected(self):
        hostname = ".".join(["a" * 63] * 4)
        result = validate_target(hostname)

        self.assertFalse(result.valid)
        self.assertEqual(result.error, "Invalid or unsupported hostname.")

    def test_none_target_is_rejected(self):
        result = validate_target(None)

        self.assertFalse(result.valid)
        self.assertEqual(result.error, "Target cannot be empty.")

    # Sprint 3: Additional IPv4 boundary-value tests

    def test_ipv4_lowest_boundary_is_accepted(self):
        result = validate_target("0.0.0.0")

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "ipv4")
        self.assertEqual(result.normalized_target, "0.0.0.0")

    def test_ipv4_highest_boundary_is_accepted(self):
        result = validate_target("255.255.255.255")

        self.assertTrue(result.valid)
        self.assertEqual(result.target_type, "ipv4")
        self.assertEqual(result.normalized_target, "255.255.255.255")


if __name__ == "__main__":
    unittest.main()
