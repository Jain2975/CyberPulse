"""tests/test_patcher.py — Unit tests for PatchingAgent patches"""
import pytest
from agents.patching_agent import PatchingAgent

# Load the real vulnerable app source for patch testing
from pathlib import Path
VULNAPP_SOURCE = (Path(__file__).parent.parent / "vulnapp" / "app.py").read_text(encoding="utf-8")


@pytest.fixture
def patcher():
    return PatchingAgent(target_url="http://localhost:5000")


def test_patch_sqli_removes_fstring(patcher):
    patched, record = patcher._patch_sqli(VULNAPP_SOURCE, {})
    assert record is not None, "Patch should have been applied"
    assert "f\"SELECT * FROM users WHERE username='{username}'" not in patched
    assert "execute(" in patched
    assert "?, ?" in patched or "(username, password)" in patched


def test_patch_path_traversal_adds_realpath(patcher):
    patched, record = patcher._patch_path_traversal(VULNAPP_SOURCE, {})
    assert record is not None
    assert "os.path.realpath" in patched
    assert "startswith" in patched


def test_patch_cmdi_removes_shell_true(patcher):
    patched, record = patcher._patch_cmdi(VULNAPP_SOURCE, {})
    assert record is not None
    # shell=True should be replaced with shell=False and list form
    assert '["ping", count_flag, "1", host]' in patched
    assert "shell=False" in patched


def test_patch_hardcoded_creds(patcher):
    patched, record = patcher._patch_hardcoded_creds(VULNAPP_SOURCE, {})
    assert record is not None
    assert "admin123" not in patched or 'os.environ.get("ADMIN_PASSWORD"' in patched


def test_patch_jwt_enforces_verification(patcher):
    patched, record = patcher._patch_jwt(VULNAPP_SOURCE, {})
    assert record is not None
    assert 'verify_signature": False' not in patched
    assert 'algorithms=["HS256"]' in patched
    assert '"none"' not in patched


def test_patch_hardcoded_creds_leaves_no_stale_symbols(patcher):
    """
    Regression: the patch used to rename only 2 of 3 references, so the patched
    app died with NameError while seeding the DB. Nothing may remain.
    """
    patched, record = patcher._patch_hardcoded_creds(VULNAPP_SOURCE, {})
    assert record is not None
    assert "HARDCODED_ADMIN_PASSWORD" not in patched
    assert "admin123" not in patched
    # every original reference is now the new name
    assert patched.count("ADMIN_PASSWORD") >= 3


def test_patch_hardcoded_creds_keeps_app_runnable(patcher):
    """
    Regression: the patch used to raise RuntimeError when the env var was unset,
    which meant vulnapp_patched/app.py could not start at all.
    """
    patched, _ = patcher._patch_hardcoded_creds(VULNAPP_SOURCE, {})
    assert "raise RuntimeError" not in patched
    assert "secrets.token_urlsafe" in patched  # random fallback instead of a known secret
    assert 'os.environ.get("ADMIN_PASSWORD")' in patched
    # constants needed by the patched code must be imported
    assert "import secrets" in patched
    assert "import hmac" in patched
    assert "hmac.compare_digest" in patched


def test_patch_runtime_config_makes_port_configurable(patcher):
    """The patched app must be able to run on 5001 next to the original target."""
    patched, record = patcher._patch_runtime_config(VULNAPP_SOURCE)
    assert record is not None
    assert "debug=True" not in patched
    assert 'os.environ.get("PORT", "5001")' in patched
    assert 'os.environ.get("HOST", "127.0.0.1")' in patched


def test_patch_runtime_config_seeds_module_relative_files_dir(patcher):
    """Legitimate /file reads must keep working after remediation."""
    patched, _ = patcher._patch_runtime_config(VULNAPP_SOURCE)
    assert 'os.makedirs("files", exist_ok=True)' not in patched
    assert "os.path.dirname(os.path.abspath(__file__))" in patched


def test_fully_patched_source_has_no_stale_references(patcher):
    """
    End-to-end guard for the bug that broke vulnapp_patched: applying every patch
    in sequence must not leave identifiers or known secrets behind.
    """
    from tests.test_patcher import VULNAPP_SOURCE as src
    patched = src
    for patch_fn in [
        patcher._patch_sqli,
        patcher._patch_path_traversal,
        patcher._patch_csrf,
        patcher._patch_cmdi,
        patcher._patch_hardcoded_creds,
        patcher._patch_jwt,
    ]:
        patched, _ = patch_fn(patched, {})
    patched, _ = patcher._patch_runtime_config(patched)

    assert "HARDCODED_ADMIN_PASSWORD" not in patched
    assert "admin123" not in patched
    assert "verify_signature" not in patched
    assert "shell=True," not in patched          # code uses shell=False (comment may mention it)
    assert "debug=True" not in patched


def test_clear_dir_removes_contents_but_keeps_directory(patcher, tmp_path):
    """_clear_dir must not delete the folder itself (Windows keeps a handle on it)."""
    target = tmp_path / "patched"
    (target / "templates").mkdir(parents=True)
    (target / "app.py").write_text("x", encoding="utf-8")
    (target / "templates" / "login.html").write_text("y", encoding="utf-8")

    patcher._clear_dir(target)

    assert target.exists()
    assert list(target.iterdir()) == []


def test_setup_patched_dir_ignores_pycache(patcher, monkeypatch, tmp_path):
    """A rebuilt patched dir must not inherit __pycache__ from vulnapp/."""
    import agents.patching_agent as pa

    src = tmp_path / "vulnapp"
    (src / "__pycache__").mkdir(parents=True)
    (src / "app.py").write_text("# app", encoding="utf-8")
    (src / "__pycache__" / "app.cpython-311.pyc").write_bytes(b"\x00")

    monkeypatch.setattr(pa, "VULNAPP_DIR", src)
    monkeypatch.setattr(pa, "PATCHED_DIR", tmp_path / "patched")

    patcher._setup_patched_dir()

    assert (tmp_path / "patched" / "app.py").exists()
    assert not (tmp_path / "patched" / "__pycache__").exists()


MINIMAL_OK_APP = '''
import os
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5001")), debug=False)
'''

MINIMAL_BROKEN_APP = '''
raise RuntimeError("this app cannot start")
'''


def test_verify_patched_app_passes_for_working_app(patcher, tmp_path):
    """The verifier must actually boot the app and confirm /health responds."""
    app_file = tmp_path / "app.py"
    app_file.write_text(MINIMAL_OK_APP, encoding="utf-8")

    result = patcher._verify_patched_app(app_file)

    assert result["syntax_ok"] is True
    assert result["hygiene_ok"] is True
    assert result["smoke_test"] == "passed", result["smoke_detail"]


def test_verify_patched_app_fails_for_unstartable_app(patcher, tmp_path):
    """A patch that produces a non-starting app must be reported, not ignored."""
    app_file = tmp_path / "app.py"
    app_file.write_text(MINIMAL_BROKEN_APP, encoding="utf-8")

    result = patcher._verify_patched_app(app_file)

    assert result["syntax_ok"] is True
    assert result["smoke_test"] == "failed"
    assert "RuntimeError" in result["smoke_detail"]


def test_verify_patched_app_flags_stale_credentials(patcher, tmp_path):
    """Leftover known secrets must fail the hygiene check."""
    app_file = tmp_path / "app.py"
    app_file.write_text('ADMIN_PASSWORD = "admin123"\n', encoding="utf-8")

    result = patcher._verify_patched_app(app_file)

    assert result["hygiene_ok"] is False
    assert "admin123" in result["stale_symbols"]


def test_free_port_returns_usable_port(patcher):
    port = patcher._free_port()
    assert isinstance(port, int) and 1024 < port <= 65535


def test_all_patches_produce_valid_python(patcher):
    """Apply all patches sequentially and ensure the result is valid Python."""
    import ast
    source = VULNAPP_SOURCE
    for patch_fn in [
        patcher._patch_sqli,
        patcher._patch_path_traversal,
        patcher._patch_cmdi,
        patcher._patch_hardcoded_creds,
        patcher._patch_jwt,
    ]:
        source, _ = patch_fn(source, {})

    try:
        ast.parse(source)
    except SyntaxError as e:
        pytest.fail(f"Patched source is not valid Python: {e}")
