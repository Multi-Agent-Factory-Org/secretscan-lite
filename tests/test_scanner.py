"""Tests du coeur d'analyse : cas positifs, cas négatifs et masquage."""

from __future__ import annotations

import json
import random
import string
import subprocess
import sys
from pathlib import Path

import pytest

from secretscan_lite.scanner import (
    AWS_KEY_RE,
    GITHUB_TOKEN_RE,
    MAX_FILE_BYTES,
    Finding,
    mask_secret,
    scan_directory,
    scan_text,
)

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
SECRET_KEYWORD = "se" + "cret"


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


GITHUB_TOKEN, AWS_KEY, GENERIC_SECRET = (
    fake_secret("ghp_", 36, "github-token"),
    fake_secret("AKIA", 16, "aws-key"),
    fake_secret("", 20, "generic"),
)
PASSWORD_VALUE = "hunter2xyz"

ALL_SECRETS = (GITHUB_TOKEN, AWS_KEY, GENERIC_SECRET, PASSWORD_VALUE)

DIRTY_FILES = {
    "config/settings.py": (
        "# configuration de démonstration\n"
        f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n'
        f'{PASSWORD_KEYWORD.upper()} = "{PASSWORD_VALUE}"\n'
    ),
    "src/deep/app.py": (
        f'def connect():\n    token = "{GITHUB_TOKEN}"\n    session = "{GENERIC_SECRET}"\n'
    ),
}

CLEAN_FILES = {
    "README.txt": (
        "Ce dossier ne contient aucun secret.\nIl sert de cas négatif pour la détection.\n"
    ),
    "main.py": ("def addition(a, b):\n    return a + b\n"),
}


def write_tree(root: Path, files: dict[str, str]) -> Path:
    """Écrit une arborescence de fichiers de test sous ``root``."""
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


# --- Cas positifs --------------------------------------------------------


def test_github_token_detected(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": f"token={GITHUB_TOKEN}\n"})
    findings = scan_directory(tmp_path)
    assert [finding.kind for finding in findings] == ["github_token"]


def test_aws_key_detected(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": f"AWS_KEY = '{AWS_KEY}'\n"})
    findings = scan_directory(tmp_path)
    assert [finding.kind for finding in findings] == ["aws_key"]


def test_password_assignment_detected(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": f'{PASSWORD_KEYWORD} = "{PASSWORD_VALUE}"\n'})
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0].kind == "password_assignment"


def test_password_accepts_colon_and_single_quotes(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": f"{SECRET_KEYWORD}: '{PASSWORD_VALUE}'\n"})
    findings = scan_directory(tmp_path)
    assert [finding.kind for finding in findings] == ["password_assignment"]


def test_generic_high_entropy_detected(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": f"valeur = {GENERIC_SECRET}\n"})
    findings = scan_directory(tmp_path)
    assert [finding.kind for finding in findings] == ["generic_high_entropy"]


def test_dirty_tree_detects_nested_secrets(tmp_path: Path) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    findings = scan_directory(tmp_path)

    assert len(findings) == 4
    assert {finding.kind for finding in findings} == {
        "github_token",
        "aws_key",
        "password_assignment",
        "generic_high_entropy",
    }
    assert {finding.path for finding in findings} == {
        "config/settings.py",
        "src/deep/app.py",
    }
    # La clé AWS ne doit pas être rapportée deux fois (spécifique + générique).
    aws = [finding for finding in findings if finding.kind == "aws_key"]
    assert len(aws) == 1


def test_findings_are_reported_with_line_numbers(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": f"ligne1\nligne2\nTOKEN = {GITHUB_TOKEN}\n"})
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 3
    assert findings[0].column == len("TOKEN = ") + 1


def test_scan_directory_accepts_a_single_file(tmp_path: Path) -> None:
    target = write_tree(tmp_path, {"f.txt": f"TOKEN={GITHUB_TOKEN}\n"}) / "f.txt"
    findings = scan_directory(target)
    assert len(findings) == 1
    assert findings[0].path == "f.txt"


def test_results_are_deterministically_ordered(tmp_path: Path) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    first = scan_directory(tmp_path)
    second = scan_directory(tmp_path)
    assert first == second
    assert first == sorted(first, key=lambda f: (f.path, f.line, f.column))


# --- Cas négatifs --------------------------------------------------------


def test_clean_tree_reports_nothing(tmp_path: Path) -> None:
    write_tree(tmp_path, CLEAN_FILES)
    assert scan_directory(tmp_path) == []


def test_clean_tree_ignores_short_and_uniform_tokens(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "f.txt": (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  # 32 lettres, aucun chiffre
                "12345678901234567890123456789012\n"  # 32 chiffres, aucune lettre
                "abcdefghijklmnopqrs\n"  # 19 caractères alphanumériques
                "note=abcdefghij\n"  # valeur courte
                "password = sans_guillemets\n"  # affectation non guillemetée
            )
        },
    )
    assert scan_directory(tmp_path) == []


def test_binary_file_is_skipped(tmp_path: Path) -> None:
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\x00\x01\x02" + GITHUB_TOKEN.encode() + b"\x00")
    assert scan_directory(tmp_path) == []


def test_non_utf8_file_is_skipped(tmp_path: Path) -> None:
    content = "mot de passe café".encode("latin-1") + b"\n" + f"TOKEN={GITHUB_TOKEN}".encode()
    (tmp_path / "latin1.txt").write_bytes(content)
    assert scan_directory(tmp_path) == []


def test_oversized_file_is_skipped(tmp_path: Path) -> None:
    payload = f"TOKEN={GITHUB_TOKEN}\n".encode() + b" " * MAX_FILE_BYTES
    (tmp_path / "huge.txt").write_bytes(payload)
    assert scan_directory(tmp_path) == []


def test_broken_symlink_is_ignored(tmp_path: Path) -> None:
    write_tree(tmp_path, {"ok.txt": f"TOKEN={GITHUB_TOKEN}\n"})
    (tmp_path / "lien.txt").symlink_to(tmp_path / "cible-absente.txt")
    findings = scan_directory(tmp_path)
    assert [finding.path for finding in findings] == ["ok.txt"]


def test_excluded_directories_are_skipped(tmp_path: Path) -> None:
    write_tree(tmp_path, {".git/objects/x.txt": f"TOKEN={GITHUB_TOKEN}\n"})
    write_tree(tmp_path, {"real.txt": f"TOKEN={GITHUB_TOKEN}\n"})
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0].path == "real.txt"


def test_missing_path_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_directory(tmp_path / "absent")


# --- Masquage ------------------------------------------------------------


def test_masking_never_reveals_the_full_value() -> None:
    for secret in ALL_SECRETS:
        masked = mask_secret(secret)
        assert masked != secret
        assert secret not in masked


def test_short_values_are_fully_masked() -> None:
    assert mask_secret(PASSWORD_VALUE) == "*" * len(PASSWORD_VALUE)


def test_long_values_keep_only_the_edges() -> None:
    masked = mask_secret(GITHUB_TOKEN)
    assert masked.startswith(GITHUB_TOKEN[:4])
    assert masked.endswith(GITHUB_TOKEN[-4:])
    assert masked.count("*") == len(GITHUB_TOKEN) - 8


def test_empty_value_masks_to_empty_string() -> None:
    assert mask_secret("") == ""


def test_findings_never_carry_the_raw_value(tmp_path: Path) -> None:
    write_tree(tmp_path, DIRTY_FILES)
    report = json.dumps([finding.masked for finding in scan_directory(tmp_path)])
    for secret in ALL_SECRETS:
        assert secret not in report


# --- Analyse de texte ----------------------------------------------------


def test_scan_text_returns_empty_list_on_plain_prose() -> None:
    assert scan_text("Le petit chat dort paisiblement.\n", "f.txt") == []


def test_scan_text_assigns_the_given_path() -> None:
    findings = scan_text(f"TOKEN={GITHUB_TOKEN}\n", "custom/path.txt")
    assert findings[0].path == "custom/path.txt"


def test_finding_is_immutable() -> None:
    finding = Finding(path="f.txt", line=1, column=1, kind="aws_key", masked="AKIA********")
    with pytest.raises(AttributeError):
        finding.line = 2  # type: ignore[misc]


# --- Garde « aucun secret en clair » -------------------------------------


def test_test_sources_hold_no_literal_secret() -> None:
    """Garde du dépôt : les fixtures ne sont jamais écrites en clair dans les sources."""
    for source in (Path(__file__), Path(__file__).with_name("test_cli.py")):
        content = source.read_text(encoding="utf-8")
        assert GITHUB_TOKEN_RE.search(content) is None
        assert AWS_KEY_RE.search(content) is None


# --- Point d'entrée en module -------------------------------------------

SRC_DIR = Path(__file__).resolve().parents[1] / "src"


def test_package_is_importable_as_a_module() -> None:
    import os

    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    result = subprocess.run(
        [sys.executable, "-c", "import secretscan_lite; print(secretscan_lite.__version__)"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "0.1.0"
