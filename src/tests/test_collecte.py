
import unittest

from src.collecte import masquer_ip, normaliser_acces

LIGNE = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"


class TestCollecte(unittest.TestCase):

    def test_masquer_ip(self):
        self.assertEqual(
            masquer_ip("192.168.1.15"),
            "192.168.1.x"
        )

    def test_normaliser_acces(self):
        sig = normaliser_acces(LIGNE, 42)

        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.type, "LOGIN_ECHEC")


if __name__ == "__main__":
    unittest.main()