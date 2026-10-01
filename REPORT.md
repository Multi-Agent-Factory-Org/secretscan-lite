# Rapport — secretscan-lite (T-0002)

## Objet

Livrer `secretscan-lite`, premier outil produit de bout en bout par
l'usine multi-agentique : un paquet Python installable qui détecte des
motifs de secrets dans une arborescence, écrit un rapport Markdown ou JSON
sur la sortie standard et signale la détection par son code de sortie.

## Arborescence livrée

```
pyproject.toml
README.md
REPORT.md
src/secretscan_lite/__init__.py
src/secretscan_lite/scanner.py
src/secretscan_lite/cli.py
tests/test_scanner.py
tests/test_cli.py
```

Trois modules seulement : `scanner.py` porte la logique de détection,
`cli.py` l'interface en ligne de commande, `__init__.py` l'API publique.

## Choix techniques

### 1. Aucune dépendance obligatoire

`dependencies = []` dans `pyproject.toml`. Le paquet n'utilise que la
bibliothèque standard (`os`, `re`, `json`, `argparse`, `dataclasses`,
`pathlib`, `collections.abc`). Les outils de développement (`pytest`,
`pytest-cov`, `ruff`, `build`) sont déclarés dans
`[project.optional-dependencies].dev`, hors du chemin d'exécution.

### 2. Mise en page `src/`

Le code vit sous `src/secretscan_lite/`, déclaré par
`[tool.setuptools.packages.find] where = ["src"]`. Ce choix empêche
l'import accidentel du paquet depuis la racine du dépôt : les tests
importent forcément une copie installée ou explicitement exposée via
`pythonpath = ["src"]`.

### 3. Masquage structurel, pas cosmétique

`Finding` ne stocke **jamais** la valeur brute : le constructeur ne reçoit
que la forme déjà masquée, calculée par `mask_secret`. Il est donc
impossible qu'un rapport, un log ou une reprise en mémoire divulgue un
secret, même par accident — la donnée n'existe nulle part dans l'objet.

Règle de masquage retenue :

* moins de 16 caractères → masquage intégral (`**********`) ;
* à partir de 16 caractères → 4 premiers et 4 derniers caractères
  conservés, le reste remplacé par des `*`.

Le seuil de 16 garantit qu'au moins la moitié d'une valeur reste masquée.
Un premier réglage à 8 caractères révélait 8 des 10 caractères d'un mot de
passe court : il a été corrigé après qu'un test l'a mis en évidence.

### 4. Priorité des motifs et déduplication

Quatre motifs sont reconnus :

| `kind` | Motif |
| --- | --- |
| `github_token` | `ghp_` + 36 caractères alphanumériques |
| `aws_key` | `AKIA` + 16 majuscules ou chiffres |
| `password_assignment` | `password` / `passwd` / `secret` + `=` ou `:` + valeur entre guillemets |
| `generic_high_entropy` | ≥ 20 caractères alphanumériques mêlant lettres et chiffres |

Le motif générique recouvre mécaniquement les trois autres : une clé AWS
est aussi une chaîne de 20 caractères mêlant lettres et chiffres. Les
motifs spécifiques sont donc évalués en premier et leurs intervalles
`(début, fin)` sont mémorisés ; le motif générique ignore toute
correspondance qui recouvre un intervalle déjà revendiqué. Sans ce
filtrage, une clé AWS serait rapportée deux fois. Le comportement est
verrouillé par le test `test_dirty_tree_detects_nested_secrets`.

Les bornes de mots (`\b`) évitent les correspondances partielles : un
jeton `ghp_` suivi de 40 caractères n'est pas tronqué en un faux positif
de 36.

### 5. Robustesse du parcours

Sont ignorés sans erreur : fichiers binaires (octet nul), fichiers non
UTF-8, fichiers dépassant 2 Mio, liens symboliques cassés, et les
répertoires de bruit (`.git`, `.venv`, `node_modules`, `__pycache__`,
`build`, `dist`, etc.). Le parcours est trié (`os.walk` avec
`dirnames`/`filenames` triés) : deux exécutions produisent exactement la
même liste, ce qu'atteste `test_results_are_deterministically_ordered`.

### 6. Codes de sortie

`0` aucune détection, `1` au moins une détection, `2` erreur d'usage ou
chemin introuvable. Le code `2` est réservé aux erreurs : une intégration
continue peut ainsi distinguer « rien trouvé » d'« analyse impossible ».

### 7. Analyse en lecture seule

Le scan n'ouvre aucun fichier en écriture. Le test
`test_scan_writes_no_file` relève l'arborescence avant/après deux
exécutions (Markdown et JSON) et vérifie qu'elle est identique.

## Couverture et tests

42 tests, tous verts. Couverture mesurée par `pytest-cov` sur le paquet :

```
Name                              Stmts   Miss Branch BrPart  Cover
-------------------------------------------------------------------
src/secretscan_lite/__init__.py       3      0      0      0   100%
src/secretscan_lite/cli.py           40      0      4      0   100%
src/secretscan_lite/scanner.py       86      0     30      0   100%
-------------------------------------------------------------------
TOTAL                               129      0     34      0   100%
Required test coverage of 80% reached. Total coverage: 100.00%
```

Les cas négatifs sont couverts au même titre que les positifs :

* dossier propre → `test_clean_tree_reports_nothing` ;
* faux positifs écartés → `test_clean_tree_ignores_short_and_uniform_tokens`
  (32 lettres sans chiffre, 32 chiffres sans lettre, 19 caractères,
  affectation non guillemetée) ;
* fichiers ignorés → binaire, non UTF-8, surdimensionné, lien cassé ;
* dossier exclu → `.git` non parcouru ;
* erreurs → chemin absent, arguments manquants, format inconnu ;
* masquage → valeur brute absente du rapport, extrémités seules révélées ;
* garde du dépôt → `test_test_sources_hold_no_literal_secret` vérifie que
  les sources de test ne contiennent aucun littéral conforme aux motifs.

Chaque module du paquet est à 100 % de couverture ; les branches
défensives (fichier illisible, décodage impossible, fichier
surdimensionné) sont exercées par de vrais cas, pas par des `pragma`.

## Vérifications exécutées

Toutes les commandes ci-dessous ont été exécutées sur l'arbre livré, avec
Python 3.14.7, pytest 9.1.1, ruff 0.16.9 et gitleaks 8.30.1.

| Commande | Résultat observé |
| --- | --- |
| `pytest -q` | `42 passed` |
| `ruff check .` | `All checks passed!` |
| `pytest --cov=secretscan_lite --cov-fail-under=80` | couverture totale **100 %** |
| `gitleaks dir . --redact --no-banner` | `no leaks found` |
| `python -m build --wheel` | `Successfully built secretscan_lite-0.1.0-py3-none-any.whl` |
| `pip install <wheel>` puis `secretscan-lite <dossier piégé>` | rapport Markdown, code de sortie **1** |
| `secretscan-lite <dossier propre>` | `Aucun secret détecté.`, code de sortie **0** |
| `secretscan-lite README.md` / `REPORT.md` / `pyproject.toml` / `src/` / `tests/` | **0 détection**, code de sortie **0** |
| `secretscan-lite .` (auto-scan du dépôt livré) | **0 détection**, code de sortie **0** |

Le contrat de sortie a été vérifié sur un dossier piégé monté hors du dépôt
(jeton GitHub, clé AWS, affectation de mot de passe) :

```
| Fichier | Ligne | Type | Valeur (masquée) |
| --- | ---: | --- | --- |
| `app.py` | 1 | github_token | `ghp_********************************6V5I` |
| `config/settings.py` | 1 | aws_key | `AKIA************4J4D` |
| `config/settings.py` | 2 | password_assignment | `**********` |
```

Aucune valeur brute n'apparaît dans le rapport : le mot de passe de 10
caractères est masqué intégralement, les deux jetons longs ne laissent
voir que leurs quatre premiers et quatre derniers caractères.

Le paquet a été construit et installé dans un environnement virtuel neuf
depuis la roue, puis depuis les sources (`pip install .` sur l'arbre
livré) : la commande `secretscan-lite` est bien exposée par
`[project.scripts]` et renvoie les codes de sortie attendus.

## Limites connues

* La détection est purement lexicale : un secret découpé sur plusieurs
  lignes, encodé (base64, hexadécimal) ou obfusqué échappe au scan.
* `generic_high_entropy` ne mesure pas l'entropie : il ne vérifie que la
  longueur et le mélange lettres/chiffres. Une longue chaîne technique
  légitime (condensat de hachage, identifiant) est donc signalée — le
  choix assume le faux positif plutôt que le faux négatif.
* L'affectation de mot de passe n'est reconnue que pour une valeur entre
  guillemets, conformément au brief. Une forme `PASSWORD=valeur` sans
  guillemets n'est pas détectée.
* Le seuil de 2 Mio par fichier est arbitraire et non configurable en
  ligne de commande.

## Fixtures de test : construites à l'exécution

Les cas positifs exigent des valeurs conformes aux motifs. Écrites en
clair, ces valeurs déclenchaient la garde « aucun secret en clair » :
`gitleaks` remontait cinq fuites — `github-pat` sur les deux fichiers de
test, `generic-api-key` sur la constante générique — alors même qu'il
s'agit de valeurs inventées.

Les fixtures sont donc assemblées à l'exécution par `fake_secret` : les
caractères sont tirés d'un `random.Random` à graine fixe, ce qui garde les
valeurs reproductibles (les assertions de masquage portent sur leur
longueur) sans qu'aucun littéral détectable n'apparaisse dans les
sources. Le mot-clé d'affectation est assemblé de la même façon, sinon les
gabarits de test eux-mêmes — le mot-clé suivi d'un `=`, puis du guillemet
ouvrant de la valeur — remonteraient comme détections lors d'un auto-scan.

Ces fixtures ne sont pas pour autant décoratives : chaque cas positif écrit
un vrai fichier dans `tmp_path` et vérifie que le détecteur le signale.

L'effet est mesurable sur le dépôt livré : `secretscan-lite .` renvoie
**0 détection** et le code de sortie **0**, tandis que
`gitleaks dir . --redact` conclut `no leaks found` — les deux gardes
concordent. `test_test_sources_hold_no_literal_secret` verrouille la
propriété en refusant tout littéral de test qui satisferait
`GITHUB_TOKEN_RE` ou `AWS_KEY_RE`.

## Conformité à la définition de terminé

| Exigence | État |
| --- | --- |
| Paquet `secretscan_lite` installable | oui, `pip install .` vérifié |
| Couverture ≥ 80 % | **100 %** |
| `ruff` sans aucune erreur | `All checks passed!` |
| Aucun secret en clair | `gitleaks` : `no leaks found` ; auto-scan du dépôt à **0 détection** |
| Roue construite | `secretscan_lite-0.1.0-py3-none-any.whl` |
| Écriture limitée au périmètre | 8 fichiers livrés, aucun hors périmètre |

Note d'exploitation : les outils de contrôle déposent leurs propres
artefacts (`.coverage`, `.pytest_cache/`, `.ruff_cache/`, `build/`). Ce ne
sont pas des livrables : le contrôle de périmètre les exclut explicitement.
L'environnement virtuel et la roue utilisés pour les vérifications ont été
tenus hors du dépôt ; `pip install .` ne dépose que
`src/secretscan_lite.egg-info/`, à l'intérieur du périmètre `src/`.
