
from src.contract import Signal, Verdict


def est_deja_vu(sig: Signal, vus: set) -> bool:
    """Verifier si le signal a deja ete traite."""
    cle = (sig.source, sig.ip, sig.cible, sig.type, sig.message)

    if cle in vus:
        return True

    vus.add(cle)
    return False


def compter_echecs(sig: Signal, compteur: dict) -> int:
    """Compter les echecs de connexion par adresse IP."""
    if sig.type != "LOGIN_ECHEC":
        return compteur.get(sig.ip, 0)

    compteur[sig.ip] = compteur.get(sig.ip, 0) + 1
    return compteur[sig.ip]


def chercher_procedures(sig: Signal, base: dict) -> list:
    """Chercher les procedures correspondant au message."""
    texte = f"{sig.type} {sig.message}".lower()

    procedures = []

    for mot_cle, procedure in base.items():
        if mot_cle.lower() in texte:
            procedures.append(procedure)

    return procedures


def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
    """Evaluer le niveau de risque du signal."""
    gravite = sig.gravite.upper()

    if gravite == "CRITIQUE":
        return "CRITIQUE"

    if nb_echecs >= 5:
        return "CRITIQUE"

    if gravite == "ELEVEE":
        return "ELEVEE"

    if gravite == "MOYENNE":
        return "MOYENNE"

    if gravite == "FAIBLE":
        return "FAIBLE"

    return "MOYENNE"


def analyser(
    sig: Signal,
    base: dict,
    nb_echecs: int = 0
) -> Verdict:
    """Analyser le signal et produire un verdict."""
    niveau = evaluer(sig, nb_echecs)
    procedures = chercher_procedures(sig, base)

    explication = (
        f"Signal de type {sig.type}, gravite {sig.gravite}. "
        f"Nombre d'echecs : {nb_echecs}."
    )

    if procedures:
        action = " ".join(procedures)
    else:
        action = "Surveiller le signal et effectuer une analyse manuelle."

    sensible = niveau in ("ELEVEE", "CRITIQUE")

    return Verdict(
        signal_id=sig.id,
        niveau=niveau,
        explication=explication,
        action=action,
        sensible=sensible,
        sources=procedures
    )
