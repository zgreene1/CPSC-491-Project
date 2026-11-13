"""Unit tests for auth.py (SOC 2 CC6.1 — Logical Access Security)."""

from __future__ import annotations

import os
import unittest

import auth


class AuthTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["AUTH_USERNAME"] = "analyst"
        os.environ["AUTH_PASSWORD"] = "test-password-123"

    def tearDown(self) -> None:
        os.environ.pop("AUTH_USERNAME", None)
        os.environ.pop("AUTH_PASSWORD", None)

    def test_verify_credentials_accepts_the_configured_account(self) -> None:
        self.assertTrue(auth.verify_credentials("analyst", "test-password-123"))

    def test_verify_credentials_rejects_wrong_password(self) -> None:
        self.assertFalse(auth.verify_credentials("analyst", "wrong"))

    def test_verify_credentials_rejects_wrong_username(self) -> None:
        self.assertFalse(auth.verify_credentials("not-analyst", "test-password-123"))

    def test_issued_token_verifies_to_the_same_username(self) -> None:
        token, _ = auth.issue_token("analyst")
        self.assertEqual(auth.verify_token(token), "analyst")

    def test_tampered_token_is_rejected(self) -> None:
        token, _ = auth.issue_token("analyst")
        tampered = token[:-1] + ("x" if token[-1] != "x" else "y")
        with self.assertRaises(auth.AuthError):
            auth.verify_token(tampered)

    def test_malformed_token_is_rejected(self) -> None:
        with self.assertRaises(auth.AuthError):
            auth.verify_token("not-a-real-token")

    def test_missing_token_is_rejected(self) -> None:
        with self.assertRaises(auth.AuthError):
            auth.verify_token(None)

    def test_expired_token_is_rejected(self) -> None:
        token, _ = auth.issue_token("analyst", ttl_seconds=-1)
        with self.assertRaises(auth.AuthError):
            auth.verify_token(token)

    def test_invalidated_token_is_rejected_even_before_expiry(self) -> None:
        token, _ = auth.issue_token("analyst", ttl_seconds=3600)
        auth.invalidate_token(token)
        with self.assertRaises(auth.AuthError):
            auth.verify_token(token)

    def test_extract_bearer_token_parses_the_header(self) -> None:
        self.assertEqual(auth.extract_bearer_token("Bearer abc123"), "abc123")

    def test_extract_bearer_token_handles_missing_or_malformed_headers(self) -> None:
        self.assertIsNone(auth.extract_bearer_token(None))
        self.assertIsNone(auth.extract_bearer_token("abc123"))
        self.assertIsNone(auth.extract_bearer_token("Bearer "))


if __name__ == "__main__":
    unittest.main()
