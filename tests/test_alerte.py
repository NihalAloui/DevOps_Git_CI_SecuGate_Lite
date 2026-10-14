import unittest
from src.alerte import alerter, choisir_canal, rediger, valider_action
from src.contrat import Signal, Verdict

def exemple(sensible=True, niveau="CRITIQUE"):
    s = Signal(
        "SIG-00125",
        "2026-10-05T10:01:31Z",
        "ACCES",
        "192.168.1.15",
        "web-app",
        "LOGIN_ECHEC",
        "MOYENNE",
        "POST /login -> 401 depuis 192.168.1.x",
    )
    v = Verdict(
        "SIG-00125",
        niveau,
        "Echecs de connexion",
        "Bloquer l'IP 192.168.1.15",
        sensible,
        ["ACCES"],
    )
    return s, v

class TestAlerte(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITIQUE"), "TELEPHONE")
        self.assertEqual(choisir_canal("ELEVEE"), "SLACK")
        self.assertEqual(choisir_canal("MOYENNE"), "EMAIL")
        self.assertEqual(choisir_canal("FAIBLE"), "TABLEAU")
        with self.assertRaises(ValueError):
            choisir_canal("INCONNU")

    def test_rediger(self):
        s, v = exemple()
        texte = rediger(s, v)
        self.assertIn("[CRITIQUE] Cible: web-app", texte)
        self.assertIn("Action proposee: Bloquer l'IP 192.168.1.15", texte)
        self.assertEqual(len(texte.split("\n")), 5)

    def test_alerter(self):
        s, v = exemple()
        journal = []
        al = alerter(s, v, journal)
        self.assertEqual(al.signal_id, "SIG-00125")
        self.assertEqual(al.canal, "TELEPHONE")
        self.assertEqual(al.destinataire, "equipe-secu")
        self.assertEqual(len(journal), 1)
        self.assertEqual(s.statut, "ALERTE")

    def test_validation(self):
        v_sensible = exemple(sensible=True)[1]
        self.assertTrue(valider_action(v_sensible, " OUI "))
        self.assertTrue(valider_action(v_sensible, "ok"))
        self.assertTrue(valider_action(v_sensible, "yes"))
        self.assertFalse(valider_action(v_sensible, "n"))

        v_non_sensible = exemple(sensible=False, niveau="FAIBLE")[1]
        self.assertTrue(valider_action(v_non_sensible, "n"))

if __name__ == "__main__":
    unittest.main()