#!/usr/bin/env python3
"""Vérification du livrable, et rapport à schéma versionné.

Trois contrôles, dont celui qui compte le plus pour un livrable : le **test de déploiement**.
Lancer les tests dans le dossier des sources ne teste pas le colis — le langage met le dossier
courant en tête de son chemin de recherche, donc les tests importent les FICHIERS du dossier,
jamais le paquet INSTALLÉ. Les défauts qui n'apparaissent qu'après installation restent invisibles.
Ce contrôle-ci construit la roue, l'installe dans un environnement neuf, et exécute l'outil.

Usage : python3 scripts/verifier.py [--rapport chemin]
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

RACINE = Path(__file__).resolve().parent.parent
SECRETS = (
    re.compile(r"\b(gh[psoru]_[A-Za-z0-9]{16,})\b"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
)


def nettoyer(texte: str) -> str:
    texte = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", texte)
    for motif in SECRETS:
        texte = motif.sub("[MASQUÉ]", texte)
    return texte


def lancer(commande: list[str]) -> tuple[int, str]:
    try:
        resultat = subprocess.run(commande, cwd=RACINE, capture_output=True, text=True, timeout=900)
    except FileNotFoundError:
        return 127, f"commande introuvable : {commande[0]}"
    except subprocess.TimeoutExpired:
        return 124, "délai dépassé"
    lignes = [x.strip() for x in (resultat.stdout + resultat.stderr).splitlines() if x.strip()]
    return resultat.returncode, nettoyer(lignes[-1] if lignes else "(aucune sortie)")[:200]


def test_de_deploiement() -> tuple[int, str]:
    """Construit la roue, l'installe dans un environnement neuf, exécute l'outil."""
    travail = Path(tempfile.mkdtemp(prefix="deploiement-"))
    try:
        code, resume = lancer([sys.executable, "-m", "build", "--wheel",
                               "--outdir", str(travail / "dist")])
        if code:
            return code, f"construction échouée : {resume}"
        roues = list((travail / "dist").glob("*.whl"))
        if not roues:
            return 1, "aucune roue produite"

        code, resume = lancer([sys.executable, "-m", "venv", str(travail / "venv")])
        if code:
            return code, f"environnement neuf impossible : {resume}"
        python = travail / "venv/bin/python3"
        code, resume = lancer([str(python), "-m", "pip", "install", "--quiet", str(roues[0])])
        if code:
            return code, f"installation de la roue échouée : {resume}"

        outil = travail / "venv/bin/secretscan-lite"
        if not outil.exists():
            return 1, "l'outil installé est introuvable"
        code, resume = lancer([str(outil), "--help"])
        if code:
            return code, f"l'outil installé ne démarre pas : {resume}"

        # détecte un secret, et reste silencieux sur un dossier propre
        (travail / "avec").mkdir()
        (travail / "avec/f.txt").write_text('cle = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        (travail / "sans").mkdir()
        (travail / "sans/g.txt").write_text("rien a signaler\n", encoding="utf-8")
        sortie_avec = subprocess.run([str(outil), str(travail / "avec")],
                                     capture_output=True, text=True).stdout
        sortie_sans = subprocess.run([str(outil), str(travail / "sans")],
                                     capture_output=True, text=True).stdout
        if "**1**" not in sortie_avec:
            return 1, "le secret n'a pas été détecté"
        if "**0**" not in sortie_sans:
            return 1, "faux positif sur un dossier propre"
        return 0, "roue construite, installée, outil exécuté, détection conforme"
    finally:
        shutil.rmtree(travail, ignore_errors=True)


def main() -> int:
    analyseur = argparse.ArgumentParser(prog="verifier", description="Vérification du livrable")
    analyseur.add_argument("--rapport", default=str(RACINE / "rapport-ci.json"))
    args = analyseur.parse_args()

    debut = time.monotonic()
    controles = []
    for nom, description, commande in (
        ("style", "Style du code", [sys.executable, "-m", "ruff", "check", "."]),
        ("tests", "Suite de tests", [sys.executable, "-m", "pytest", "-q"]),
    ):
        code, resume = lancer(commande)
        controles.append({"nom": nom, "bloquant": True, "code": code, "resume": resume})
        print(f"  {'✔' if code == 0 else '✘'} {description:24s} {resume[:66]}")

    code, resume = test_de_deploiement()
    controles.append({"nom": "deploiement", "bloquant": True, "code": code, "resume": resume})
    print(f"  {'✔' if code == 0 else '✘'} {'Test de déploiement':24s} {resume[:66]}")

    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=RACINE,
                            capture_output=True, text=True).stdout.strip()
    rouge = any(c["code"] != 0 for c in controles)
    rapport = {
        "version": 1,
        "commit": commit,
        "branche": subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=RACINE,
                                  capture_output=True, text=True).stdout.strip(),
        "verdict": "rouge" if rouge else "vert",
        "controles": controles,
        "produit_ou": {
            "machine": socket.gethostname(),
            "systeme": f"{platform.system()} {platform.release()}",
            "langage": platform.python_version(),
            "horodatage": datetime.now(ZoneInfo("Europe/Paris")).strftime("%Y-%m-%d à %H:%M"),
        },
        "duree_s": round(time.monotonic() - debut, 1),
    }
    Path(args.rapport).write_text(json.dumps(rapport, ensure_ascii=False, indent=2) + "\n",
                                  encoding="utf-8")
    print(f"\nverdict : {rapport['verdict'].upper()} — rapport écrit dans {args.rapport}")
    return 1 if rouge else 0


if __name__ == "__main__":
    raise SystemExit(main())
