from src.contrat import Alerte, Signal, Verdict

def choisir_canal(niveau: str) -> str:
    canaux = {
        "CRITIQUE": "TELEPHONE",
        "ELEVEE": "SLACK",
        "MOYENNE": "EMAIL",
        "FAIBLE": "TABLEAU",
    }
    if niveau not in canaux:
        raise ValueError(f"Niveau inconnu : {niveau}")
    return canaux[niveau]

def rediger(sig: Signal, verdict: Verdict) -> str:
    sources_str = ", ".join(verdict.sources)
    lignes = [
        f"[{verdict.niveau}] Cible: {sig.cible}",
        f"Signal: {sig.message}",
        f"Explication: {verdict.explication}",
        f"Action proposee: {verdict.action}",
        f"Sources: {sources_str}",
    ]
    return "\n".join(lignes)

def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    canal = choisir_canal(verdict.niveau)
    texte = rediger(sig, verdict)
    nouvelle_alerte = Alerte(
        signal_id=sig.id,
        canal=canal,
        destinataire="equipe-secu",
        texte=texte,
    )
    journal.append(nouvelle_alerte)
    sig.statut = "ALERTE"
    return nouvelle_alerte

def valider_action(verdict: Verdict, reponse: str) -> bool:
    if not verdict.sensible:
        return True
    return reponse.strip().lower() in {"o", "oui", "ok", "yes"}