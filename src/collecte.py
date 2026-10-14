import re
from src.contrat import Signal


def masquer_ip(ip: str) -> str:
    parties = ip.strip().split(".")
    if len(parties) != 4:
        raise ValueError(f"Adresse IP invalide (doit avoir 4 parties) : {ip}")
    return f"{parties[0]}.{parties[1]}.{parties[2]}.x"


def masquer_parametres(chemin: str) -> str:
    pattern = re.compile(r"(?i)\b(token|password|session|key)=([^&\s]*)")
    return pattern.sub(r"\1=[MASQUE]", chemin)


def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    champs = ligne.strip().split()
    if len(champs) < 6:
        raise ValueError(f"Ligne d'accès invalide (moins de 6 champs) : {ligne}")

    date_str, heure_str, ip, methode, chemin, statut = champs[:6]
    timestamp = f"{date_str}T{heure_str}Z"
    id_sig = f"SIG-{numero:05d}"

    chemin_sans_params = chemin.split("?")[0]
    if chemin_sans_params == "/login" and statut in ("401", "403"):
        type_sig = "LOGIN_ECHEC"
    else:
        type_sig = "ACCES"

    if statut.startswith("5"):
        gravite = "ELEVEE"
    elif statut.startswith("4"):
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"

    chemin_masque = masquer_parametres(chemin)
    ip_masquee = masquer_ip(ip)
    message = f"{methode} {chemin_masque} -> {statut} depuis {ip_masquee}"

    return Signal(
        id=id_sig,
        timestamp=timestamp,
        source="ACCES",
        ip=ip,
        cible=cible,
        type=type_sig,
        gravite=gravite,
        message=message,
        statut="NOUVEAU",
    )


def normaliser_scan(rapport: dict, numero: int) -> Signal:
    cles_requises = ["rule", "component", "severity", "message", "date"]
    for cle in cles_requises:
        if cle not in rapport:
            raise ValueError(f"Clé manquante dans le rapport de scan : {cle}")

    sev = str(rapport["severity"]).lower()
    if sev == "blocker":
        gravite = "CRITIQUE"
    elif sev == "critical":
        gravite = "ELEVEE"
    elif sev == "major":
        gravite = "MOYENNE"
    elif sev == "minor":
        gravite = "FAIBLE"
    else:
        gravite = "FAIBLE"

    id_sig = f"SIG-{numero:05d}"
    message = f"Faille {rapport['rule']} : {rapport['message']}"

    return Signal(
        id=id_sig,
        timestamp=rapport["date"],
        source="SCAN",
        ip="",
        cible=rapport["component"],
        type="FAILLE",
        gravite=gravite,
        message=message,
        statut="NOUVEAU",
    )
