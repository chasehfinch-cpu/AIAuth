"""Shared pytest configuration for AIAuth tests.

Redirects the server's DB, registry, and key paths to a temp directory
BEFORE the server module is imported. This keeps tests from touching
your production aiauth.db / aiauth_registry.db / keys/ layout.

If more test modules land (PR 7 full suite), keep this file single-
purposed: env-var redirection + a session-scoped temp root. Per-test
fixtures belong in the module that uses them.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# A single temp root shared by the whole test session. Created at import
# time (before pytest collects) so it's already in os.environ when the
# server module loads.
_TMP_ROOT = Path(tempfile.mkdtemp(prefix="aiauth-tests-"))

os.environ["AIAUTH_DB_PATH"] = str(_TMP_ROOT / "aiauth.db")
os.environ["AIAUTH_REGISTRY_PATH"] = str(_TMP_ROOT / "registry.db")
os.environ["AIAUTH_KEY_DIR"] = str(_TMP_ROOT)
os.environ.setdefault("SERVER_SECRET", "pytest-server-secret-do-not-use-in-prod")
os.environ.setdefault("AIAUTH_MASTER_KEY", "pytest-master-key")
os.environ.setdefault("AIAUTH_PUBLIC_URL", "http://localhost")
# Skip optional outbound integrations during tests.
os.environ.setdefault("RESEND_API_KEY", "")
os.environ.setdefault("AIAUTH_OPERATOR_EMAIL", "test@example.invalid")

# Make the repo root importable so `import server` works regardless of
# where pytest was invoked.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
