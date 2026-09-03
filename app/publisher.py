"""
Picks the real SCM adapter or the mock/demo adapter, based on THREATGATE_DEMO_MODE.
Both modules expose the same two functions: publish_content() and ensure_edl_object().
"""

import os


def get_publisher():
    demo_mode = os.environ.get("THREATGATE_DEMO_MODE", "true").lower() == "true"
    if demo_mode:
        from adapters import mock_scm
        return mock_scm
    from adapters import scm_write
    return scm_write


def is_demo_mode() -> bool:
    return os.environ.get("THREATGATE_DEMO_MODE", "true").lower() == "true"
