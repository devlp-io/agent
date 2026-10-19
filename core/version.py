"""
core.version — SOM-SCAN version and build sequence metadata.
Increments sequentially on updates to maintain professional release cadence.
"""
__version__ = "8.5.8"
__build__ = "2026.10.19-release"


def get_version_string() -> str:
    return f"v{__version__}"


def get_full_version() -> str:
    return f"SOM-SCAN v{__version__} ({__build__})"
