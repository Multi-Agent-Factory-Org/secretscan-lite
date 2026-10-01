"""Interface en ligne de commande ``secretscan-lite``.

Le rapport est écrit sur la sortie standard ; rien n'est écrit sur le
disque. Le code de sortie encode le résultat :

* ``0`` — aucune détection ;
* ``1`` — au moins une détection ;
* ``2`` — erreur d'usage ou chemin invalide.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict

from secretscan_lite.scanner import Finding, scan_directory

__all__ = ["EXIT_CLEAN", "EXIT_FINDINGS", "EXIT_USAGE", "build_parser", "main"]

#: Aucune détection.
EXIT_CLEAN = 0
#: Au moins une détection.
EXIT_FINDINGS = 1
#: Usage invalide ou chemin introuvable.
EXIT_USAGE = 2

FORMATS = ("markdown", "json")


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments de la commande."""
    parser = argparse.ArgumentParser(
        prog="secretscan-lite",
        description="Détecte des motifs de secrets dans un fichier ou une arborescence.",
    )
    parser.add_argument("path", help="fichier ou répertoire à analyser")
    parser.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default="markdown",
        help="format du rapport (défaut : markdown)",
    )
    return parser


def render_markdown(path: str, findings: Sequence[Finding]) -> str:
    """Rend le rapport au format Markdown.

    Args:
        path: Chemin analysé, tel que fourni par l'utilisateur.
        findings: Détections à rapporter.

    Returns:
        Le rapport, terminé par un saut de ligne.
    """
    lines = [
        "# secretscan-lite — rapport",
        "",
        f"Chemin analysé : `{path}`",
        "",
        f"Détections : **{len(findings)}**",
        "",
    ]
    if not findings:
        lines.append("Aucun secret détecté.")
    else:
        lines.extend(
            [
                "| Fichier | Ligne | Type | Valeur (masquée) |",
                "| --- | ---: | --- | --- |",
            ]
        )
        for finding in findings:
            lines.append(
                f"| `{finding.path}` | {finding.line} | {finding.kind} | `{finding.masked}` |"
            )
    lines.append("")
    return "\n".join(lines)


def render_json(path: str, findings: Sequence[Finding]) -> str:
    """Rend le rapport au format JSON.

    Args:
        path: Chemin analysé, tel que fourni par l'utilisateur.
        findings: Détections à rapporter.

    Returns:
        Le rapport JSON indenté, terminé par un saut de ligne.
    """
    payload = {
        "path": path,
        "count": len(findings),
        "findings": [asdict(finding) for finding in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


_RENDERERS = {"markdown": render_markdown, "json": render_json}


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée de la commande ``secretscan-lite``.

    Args:
        argv: Arguments de ligne de commande, sans le nom du programme.
            ``None`` laisse ``argparse`` lire ``sys.argv``.

    Returns:
        Le code de sortie : ``0``, ``1`` ou ``2``.
    """
    args = build_parser().parse_args(argv)
    try:
        findings = scan_directory(args.path)
    except FileNotFoundError as exc:
        print(f"secretscan-lite: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:  # pragma: no cover - erreur d'E/S rare
        print(f"secretscan-lite: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = _RENDERERS[args.format](args.path, findings)
    sys.stdout.write(report)
    return EXIT_FINDINGS if findings else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover - exécuté en sous-processus
    raise SystemExit(main())
