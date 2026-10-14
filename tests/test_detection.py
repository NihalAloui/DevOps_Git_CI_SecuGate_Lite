import unittest

from src.contrat import Signal
from src.detection import (
    est_deja_vu,
    compter_echecs,
    chercher_procedures,
    evaluer,
    analyser,
)
from src.contrat import PROCEDURES


def creer_signal(
    type_signal="LOGIN_ECHEC",
    timestamp="2026-10-05 10:01:10",
    ip="192.168.1.15",
    message="Echec login",
    gravite="ELEVEE",
):
    return Signal(
        id="SIG-00001",
        timestamp=timestamp,
        source="ACCES",
        ip=ip,
        cible="web-app",
        type=type_signal,
        gravite=gravite,
        message=message,
    )


class TestDetection(unittest.TestCase):

    def test_est_deja_vu(self):
        sig = creer_signal()
        vus = set()

        self.assertFalse(est_deja_vu(sig, vus))
        self.assertTrue(est_deja_vu(sig, vus))

    def test_deux_timestamps_differents(self):
        vus = set()
        sig1 = creer_signal(timestamp="10:01:10")
        sig2 = creer_signal(timestamp="10:01:11")

        self.assertFalse(est_deja_vu(sig1, vus))
        self.assertFalse(est_deja_vu(sig2, vus))

    def test_compter_echecs(self):
        compteur = {}
        sig = creer_signal()

        self.assertEqual(compter_echecs(sig, compteur), 1)
        self.assertEqual(compter_echecs(sig, compteur), 2)
        self.assertEqual(compteur["192.168.1.15"], 2)

    def test_non_login_ne_compte_pas(self):
        compteur = {}
        sig = creer_signal(type_signal="ACCES")

        self.assertEqual(compter_echecs(sig, compteur), 0)
        self.assertEqual(compteur, {})

    def test_chercher_procedures_sans_casse(self):
        sig = creer_signal(message="Tentative LOGIN detectee")
        resultat = chercher_procedures(sig, PROCEDURES)

        self.assertEqual(len(resultat), 1)
        self.assertEqual(resultat[0], PROCEDURES["login"])

    def test_aucune_procedure(self):
        sig = creer_signal(message="Evenement inconnu")
        self.assertEqual(chercher_procedures(sig, {}), [])

    def test_evaluer_login_moyenne(self):
        sig = creer_signal()
        self.assertEqual(evaluer(sig, 4), "MOYENNE")

    def test_evaluer_login_critique(self):
        sig = creer_signal()
        self.assertEqual(evaluer(sig, 5), "CRITIQUE")

    def test_evaluer_autre_type(self):
        sig = creer_signal(type_signal="FAILLE", gravite="ELEVEE")
        self.assertEqual(evaluer(sig), "ELEVEE")

    def test_analyser(self):
        sig = creer_signal(message="Echec login")
        verdict = analyser(sig, PROCEDURES, 5)

        self.assertEqual(verdict.signal_id, sig.id)
        self.assertEqual(verdict.niveau, "CRITIQUE")
        self.assertEqual(verdict.action, "Bloquer l'IP 192.168.1.15")
        self.assertTrue(verdict.sensible)
        self.assertEqual(verdict.sources, ["ACCES"])
        self.assertEqual(sig.statut, "ANALYSE")


if __name__ == "__main__":
    unittest.main()
