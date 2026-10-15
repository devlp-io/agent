"""
core.version — SOM-SCAN version and build sequence metadata.
Increments sequentially on updates to maintain professional release cadence.
"""
__version__ = "8.5.7"
__build__ = "2026.10.15-vortex-ui-resilience"


def get_version_string() -> str:
    return f"v{__version__}"


def get_full_version() -> str:
    return f"SOM-SCAN v{__version__} ({__build__})"
