"""secretscan_lite — détection de motifs de secrets dans une arborescence.

L'API publique tient en deux symboles :

    >>> from secretscan_lite import Finding, scan_directory
    >>> findings = scan_directory(".")

Le scan est en lecture seule : aucun fichier n'est créé ni modifié.
"""

from secretscan_lite.scanner import Finding, scan_directory

__all__ = ["Finding", "scan_directory", "__version__"]

__version__ = "0.1.0"
