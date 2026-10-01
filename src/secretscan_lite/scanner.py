"""Coeur de l'analyse : parcours d'arborescence et détection de motifs.

Le module est volontairement sans dépendance : seuls ``os``, ``re``,
``dataclasses`` et ``pathlib`` sont utilisés.

Aucune valeur de secret n'est conservée en clair : seul le masque est
stocké dans :class:`Finding`. Le scan n'écrit jamais sur le disque.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Finding",
    "PATTERN_ORDER",
    "mask_secret",
    "scan_directory",
]

#: Caractère utilisé pour masquer les valeurs détectées.
MASK_CHAR = "*"

#: Nombre de caractères révélés en tête et en queue d'une valeur masquée.
_MASK_EDGE = 4

#: En dessous de cette longueur, la valeur est masquée intégralement.
#: À 16 caractères, les 8 caractères révélés laissent encore la moitié
#: masquée ; révéler 8 caractères d'une valeur de 10 la divulguerait.
_MASK_MIN_LENGTH = 16

#: Taille maximale d'un fichier analysé (au-delà, il est ignoré).
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Répertoires jamais parcourus (bruit, artefacts, dépôts imbriqués).
EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)

# --- Motifs de détection -------------------------------------------------
#
# Chaque expression expose un groupe nommé ``value`` : c'est le fragment
# effectivement masqué dans le rapport.

#: Jeton GitHub : ``ghp_`` suivi de 36 caractères alphanumériques.
GITHUB_TOKEN_RE = re.compile(r"(?P<value>\bghp_[A-Za-z0-9]{36}\b)")

#: Clé d'accès AWS : ``AKIA`` suivi de 16 majuscules ou chiffres.
AWS_KEY_RE = re.compile(r"(?P<value>\bAKIA[A-Z0-9]{16}\b)")

#: Affectation de mot de passe : mot-clé, ``=`` ou ``:``, valeur entre guillemets.
PASSWORD_RE = re.compile(
    r"""(?ix)
    \b(?:password|passwd|secret)\b   # mot-clé
    \s*[=:]\s*                       # séparateur
    (?P<quote>['"])                  # guillemet ouvrant
    (?P<value>[^'"]{1,200})          # valeur
    (?P=quote)                       # guillemet fermant identique
    """
)

#: Chaîne générique : 20 caractères alphanumériques ou plus, mêlant lettres et chiffres.
GENERIC_RE = re.compile(
    r"(?P<value>\b(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{20,}\b)"
)

#: Motifs « spécifiques », évalués avant le motif générique.
SPECIFIC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_token", GITHUB_TOKEN_RE),
    ("aws_key", AWS_KEY_RE),
    ("password_assignment", PASSWORD_RE),
)

#: Motif générique, utilisé uniquement hors des zones déjà couvertes.
GENERIC_PATTERN: tuple[str, re.Pattern[str]] = ("generic_high_entropy", GENERIC_RE)

#: Ordre canonique des types de détection, du plus au moins spécifique.
PATTERN_ORDER: tuple[str, ...] = tuple(kind for kind, _ in (*SPECIFIC_PATTERNS, GENERIC_PATTERN))


@dataclass(frozen=True, slots=True)
class Finding:
    """Une détection unique, localisée dans un fichier.

    La valeur du secret n'est jamais stockée : seul ``masked`` est exposé,
    ce qui rend structurellement impossible la fuite d'un secret via un
    rapport ou une reprise en log.

    Attributes:
        path: Chemin du fichier, relatif au répertoire analysé.
        line: Numéro de ligne, à partir de 1.
        column: Colonne du début de la correspondance, à partir de 1.
        kind: Type de motif détecté (voir :data:`PATTERN_ORDER`).
        masked: Valeur détectée, masquée.
    """

    path: str
    line: int
    column: int
    kind: str
    masked: str


def mask_secret(value: str) -> str:
    """Masque une valeur détectée en ne révélant au plus que ses extrémités.

    Une valeur plus courte que :data:`_MASK_MIN_LENGTH` est masquée
    intégralement : révéler la moitié d'un mot de passe de 10 caractères
    reviendrait à le divulguer.

    Args:
        value: Valeur brute détectée.

    Returns:
        Une chaîne qui n'est jamais égale à ``value`` et qui n'en dévoile
        au plus que les quatre premiers et quatre derniers caractères.
    """
    if not value:
        return ""
    if len(value) < _MASK_MIN_LENGTH:
        return MASK_CHAR * len(value)
    return f"{value[:_MASK_EDGE]}{MASK_CHAR * (len(value) - 2 * _MASK_EDGE)}{value[-_MASK_EDGE:]}"


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    """Indique si deux intervalles semi-ouverts se recouvrent."""
    return max(a[0], b[0]) < min(a[1], b[1])


def scan_text(text: str, path: str) -> list[Finding]:
    """Analyse un contenu textuel ligne à ligne.

    Les motifs spécifiques (jeton GitHub, clé AWS, affectation de mot de
    passe) sont évalués en premier ; le motif générique ne retient ensuite
    que les correspondances qui ne recouvrent aucune détection déjà
    enregistrée. Sans ce filtrage, une clé AWS serait rapportée deux fois.

    Args:
        text: Contenu du fichier.
        path: Chemin affiché dans les détections.

    Returns:
        Les détections, triées par ligne puis par colonne.
    """
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        claimed: list[tuple[int, int]] = []
        for kind, pattern in SPECIFIC_PATTERNS:
            for match in pattern.finditer(line):
                start, end = match.span("value")
                claimed.append((start, end))
                findings.append(
                    Finding(
                        path=path,
                        line=line_number,
                        column=start + 1,
                        kind=kind,
                        masked=mask_secret(match.group("value")),
                    )
                )

        kind, pattern = GENERIC_PATTERN
        for match in pattern.finditer(line):
            start, end = match.span("value")
            if any(_overlaps((start, end), span) for span in claimed):
                continue
            findings.append(
                Finding(
                    path=path,
                    line=line_number,
                    column=start + 1,
                    kind=kind,
                    masked=mask_secret(match.group("value")),
                )
            )

    findings.sort(key=lambda finding: (finding.line, finding.column, finding.kind))
    return findings


def _iter_files(root: Path) -> list[Path]:
    """Liste les fichiers analysables sous ``root``, en ordre déterministe."""
    if root.is_file():
        return [root]

    collected: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
        for filename in sorted(filenames):
            collected.append(Path(dirpath) / filename)
    return collected


def _read_text(file_path: Path) -> str | None:
    """Lit un fichier texte, ou renvoie ``None`` s'il est binaire ou illisible."""
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = file_path.read_bytes()
    except OSError:
        return None

    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_directory(path: os.PathLike[str] | str) -> list[Finding]:
    """Parcourt récursivement ``path`` et détecte les motifs de secrets.

    Les fichiers binaires, illisibles et dépassant :data:`MAX_FILE_BYTES`
    sont ignorés, tout comme les répertoires listés dans
    :data:`EXCLUDED_DIRS`. Aucun fichier n'est écrit : la fonction est en
    lecture seule.

    Args:
        path: Répertoire à parcourir, ou fichier unique à analyser.

    Returns:
        Les détections, triées par chemin, ligne puis colonne.

    Raises:
        FileNotFoundError: Si ``path`` n'existe pas.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"chemin introuvable : {root}")

    findings: list[Finding] = []
    single_file = root.is_file()
    for file_path in _iter_files(root):
        text = _read_text(file_path)
        if text is None:
            continue
        display = file_path.name if single_file else file_path.relative_to(root).as_posix()
        findings.extend(scan_text(text, display))

    findings.sort(key=lambda finding: (finding.path, finding.line, finding.column))
    return findings
