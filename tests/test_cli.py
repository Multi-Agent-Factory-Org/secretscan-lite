"""Tests de la commande ``secretscan-lite`` : rapport, format et code de sortie."""

from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys
from pathlib import Path

import pytest

from secretscan_lite.cli import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_USAGE,
    build_parser,
    main,
    render_json,
    render_markdown,
)
from secretscan_lite.scanner import Finding

# --- Valeurs de test -----------------------------------------------------
#
# Les jetons factices conformes aux motifs sont assemblés à l'exécution et
# jamais écrits en clair : la garde « aucun secret en clair » du dépôt refuse
# tout littéral détectable, même dans les tests. La génération reste
# déterministe (graine fixe) pour que les assertions de masquage, qui portent
# sur la longueur des valeurs, soient reproductibles.

_SEED_PREFIX = "secretscan-lite"
_DIGITS = string.digits
_UPPER = string.ascii_uppercase

#: Mot-clé d'affectation, assemblé lui aussi à l'exécution : écrit en clair
#: devant une valeur entre guillemets, il ferait remonter les gabarits de ce
#: fichier comme de fausses détections lors d'un auto-scan du dépôt.
PASSWORD_KEYWORD = "pass" + "word"


def fake_secret(prefix: str, body_length: int, seed: str) -> str:
    """Assemble une valeur factice conforme à un motif, sans littéral en clair.

    Les caractères sont tirés alternativement dans les chiffres et dans les
    majuscules : le corps mêle donc toujours lettres et chiffres, propriété
    qu'exige le motif générique, sans avoir à la vérifier après coup.

    Args:
        prefix: Préfixe du motif (``ghp_``, ``AKIA``, ...).
        body_length: Nombre de caractères alphanumériques après le préfixe.
        seed: Graine de génération, pour un résultat reproductible.

    Returns:
        La valeur ``prefix + corps``.
    """
    rng = random.Random(f"{_SEED_PREFIX}:{seed}")
    body = "".join(
        rng.choice(_DIGITS if index % 2 == 0 else _UPPER) for index in range(body_length)
    )
    return f"{prefix}{body}"


GITHUB_TOKEN, AWS_KEY = (
    fake_secret("ghp_", 36, "github-token"),
    fake_secret("AKIA", 16, "aws-key"),
)
PASSWORD_VALUE = "hunter2xyz"

ALL_SECRETS = (GITHUB_TOKEN, AWS_KEY, PASSWORD_VALUE)

DIRTY_FILES = {
    "config/settings.py": f'{PASSWORD_KEYWORD.upper()} = "{PASSWORD_VALUE}"\n',
    "src/app.py": f'TOKEN = "{GITHUB_TOKEN}"\nAWS_KEY = "{AWS_KEY}"\n',
}

CLEAN_FILES = {
    "README.txt": "Dossier propre, sans aucun motif suspect.\n",
    "main.py": "def addition(a, b):\n    return a + b\n",
}

SRC_DIR = Path(__file__).resolve().parents[1] / "src"


def write_tree(root: Path, files: dict[str, str]) -> Path:
    """Écrit une arborescence de fichiers de test sous ``root``."""
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def snapshot(root: Path) -> set[str]:
    """Relève l'ensemble des chemins présents sous ``root``."""
    return {path.relative_to(root).as_posix() for path in root.rglob("*")}


# --- AC-002-1 : dossier piégé -------------------------------------------


def test_dirty_directory_exits_one_and_reports_markdown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    code = main([str(tmp_path)])

    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS == 1
    assert "# secretscan-lite" in out
    assert "| Fichier | Ligne | Type | Valeur (masquée) |" in out
    assert "github_token" in out
    assert "aws_key" in out
    assert "password_assignment" in out
    assert "src/app.py" in out


def test_markdown_report_masks_every_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    main([str(tmp_path)])
    out = capsys.readouterr().out
    for secret in ALL_SECRETS:
        assert secret not in out
    assert "*" in out


def test_report_contains_one_line_per_finding(tmp_path: Path) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    findings = [
        Finding(path="a.py", line=1, column=1, kind="aws_key", masked="AKIA********"),
        Finding(path="b.py", line=2, column=3, kind="github_token", masked="ghp_****"),
    ]
    report = render_markdown(str(tmp_path), findings)
    rows = [line for line in report.splitlines() if line.startswith("| `")]
    assert len(rows) == 2
    assert rows[0].startswith("| `a.py` | 1 | aws_key |")
    assert rows[1] == "| `b.py` | 2 | github_token | `ghp_****` |"


def test_markdown_report_mentions_the_scanned_path(tmp_path: Path) -> None:
    report = render_markdown("mon/dossier", [])
    assert "mon/dossier" in report
    assert "Aucun secret détecté." in report


# --- AC-002-2 : dossier propre ------------------------------------------


def test_clean_directory_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_tree(tmp_path, CLEAN_FILES)
    code = main([str(tmp_path)])

    out = capsys.readouterr().out
    assert code == EXIT_CLEAN == 0
    assert "Aucun secret détecté." in out
    assert "Détections : **0**" in out


# --- Format JSON ---------------------------------------------------------


def test_json_format_reports_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    code = main([str(tmp_path), "--format", "json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert payload["count"] == len(payload["findings"]) == 3
    assert payload["path"] == str(tmp_path)
    assert {item["kind"] for item in payload["findings"]} == {
        "aws_key",
        "github_token",
        "password_assignment",
    }
    assert all(
        set(item) == {"path", "line", "column", "kind", "masked"} for item in payload["findings"]
    )


def test_json_format_on_clean_directory_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_tree(tmp_path, CLEAN_FILES)
    code = main([str(tmp_path), "-f", "json"])

    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_CLEAN
    assert payload["count"] == 0
    assert payload["findings"] == []


def test_json_renderer_is_valid_json_for_empty_result() -> None:
    assert json.loads(render_json("dossier", [])) == {
        "path": "dossier",
        "count": 0,
        "findings": [],
    }


# --- Erreurs d'usage -----------------------------------------------------


def test_missing_path_exits_with_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(tmp_path / "absent")])
    captured = capsys.readouterr()
    assert code == EXIT_USAGE == 2
    assert captured.out == ""
    assert "introuvable" in captured.err


def test_missing_arguments_exits_with_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == EXIT_USAGE


def test_unknown_format_is_rejected() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["dossier", "--format", "xml"])
    assert excinfo.value.code == EXIT_USAGE


def test_parser_defaults_to_markdown() -> None:
    args = build_parser().parse_args(["dossier"])
    assert args.format == "markdown"
    assert args.path == "dossier"


# --- Absence d'écriture --------------------------------------------------


def test_scan_writes_no_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    before = snapshot(tmp_path)
    main([str(tmp_path)])
    main([str(tmp_path), "--format", "json"])
    capsys.readouterr()
    assert snapshot(tmp_path) == before


# --- Commande installable, exécutée en sous-processus --------------------


def test_command_line_entry_point_in_a_subprocess(tmp_path: Path) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    result = subprocess.run(
        [sys.executable, "-m", "secretscan_lite.cli", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == EXIT_FINDINGS
    assert "github_token" in result.stdout
    assert GITHUB_TOKEN not in result.stdout


def test_command_line_entry_point_on_clean_tree(tmp_path: Path) -> None:
    write_tree(tmp_path, CLEAN_FILES)
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    result = subprocess.run(
        [sys.executable, "-m", "secretscan_lite.cli", str(tmp_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == EXIT_CLEAN
    assert json.loads(result.stdout)["count"] == 0
