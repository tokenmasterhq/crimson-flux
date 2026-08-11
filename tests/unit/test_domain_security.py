import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import xhs_insight.security as security
from xhs_insight.api.app import _write_instance_file
from xhs_insight.domain import ContentSelection, CreateJobRequest
from xhs_insight.security import CredentialCipher, redact_text, sanitize_url


def test_keyword_request_and_presets() -> None:
    request = CreateJobRequest.model_validate(
        {
            "source": {"type": "keyword", "keyword": "  露营   装备 ", "limit": 25},
            "content": {"preset": "full"},
        }
    )
    assert request.source.keyword == "露营 装备"
    assert request.content.needs_details is True
    assert len(request.content.fields) == 5


def test_custom_requires_a_field() -> None:
    with pytest.raises(ValueError):
        ContentSelection.model_validate({"preset": "custom", "fields": []})


def test_profile_url_is_allowlisted_and_scrubbed() -> None:
    request = CreateJobRequest.model_validate(
        {
            "source": {
                "type": "user",
                "profile_url": "https://www.xiaohongshu.com/user/profile/abc?xsec_token=secret",
                "all": True,
            },
            "content": {"preset": "basic"},
        }
    )
    assert request.source.profile_url == "https://www.xiaohongshu.com/user/profile/abc"
    assert request.source.profile_access == {"xsec_token": "secret"}
    assert "profile_access" not in request.source.model_dump(mode="json")
    with pytest.raises(ValueError):
        CreateJobRequest.model_validate(
            {
                "source": {"type": "user", "profile_url": "http://127.0.0.1/user/profile/a", "all": True},
                "content": {"preset": "basic"},
            }
        )
    with pytest.raises(ValueError):
        CreateJobRequest.model_validate(
            {
                "source": {
                    "type": "user",
                    "profile_url": "https://name:password@www.xiaohongshu.com/user/profile/a",
                    "all": True,
                },
                "content": {"preset": "basic"},
            }
        )


def test_cipher_roundtrip_and_url_sanitizing(tmp_path: Path) -> None:
    cipher = CredentialCipher(tmp_path / "session.key")
    envelope = cipher.encrypt_json({"cookie": "a1=secret"}, aad="auth:v1")
    assert b"secret" not in envelope
    assert cipher.decrypt_json(envelope, aad="auth:v1") == {"cookie": "a1=secret"}
    assert sanitize_url("https://example.com/note?a=1&xsec_token=nope#x") == "https://example.com/note?a=1"
    assert sanitize_url("https://user:password@example.com/note") is None
    assert sanitize_url(
        "https://example.com/note?a=1&X-Amz-Signature=nope&session_token=hidden"
    ) == "https://example.com/note?a=1"
    assert sanitize_url("javascript:alert(1)") is None
    assert redact_text('{"cookie":"a1=top-secret; web_session=hidden"}') == (
        '{"cookie":"[REDACTED]"}'
    )
    scrubbed = redact_text(
        "GET https://user:pass@example.com/note?sign=signature-secret&ok=1 "
        "via http://proxy-user:proxy-pass@proxy.invalid "
        "and https://token-only@example.net/?xsec%5Ftoken=encoded-secret-value "
        "access_token=access-secret"
    )
    assert "pass" not in scrubbed
    assert "proxy-user" not in scrubbed
    assert "token-only" not in scrubbed
    assert "encoded-secret-value" not in scrubbed
    assert "signature-secret" not in scrubbed
    assert "access-secret" not in scrubbed
    assert "]]" not in scrubbed
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "session.key").stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode-bit regression")
def test_existing_master_key_permissions_are_revalidated(tmp_path: Path) -> None:
    key_path = tmp_path / "master.key"
    CredentialCipher(key_path)
    key_path.chmod(0o644)

    CredentialCipher(key_path)

    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_master_key_symlink_is_rejected(tmp_path: Path) -> None:
    real_key = tmp_path / "real.key"
    real_key.write_bytes(os.urandom(32))
    link = tmp_path / "master.key"
    try:
        link.symlink_to(real_key)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(RuntimeError, match="符号链接"):
        CredentialCipher(link)


def _mock_windows_acl(
    monkeypatch: pytest.MonkeyPatch,
    events: list[tuple[str, Path]],
    *,
    succeed: bool,
) -> None:
    monkeypatch.setattr(security, "_is_windows", lambda: True)
    monkeypatch.setenv("USERNAME", "xhs-test-user")
    monkeypatch.delenv("USERDOMAIN", raising=False)

    def fake_icacls(command: list[str], **_kwargs: object) -> SimpleNamespace:
        candidate = Path(command[1])
        assert candidate.is_file()
        assert candidate.read_bytes() == b""
        events.append(("acl", candidate))
        return SimpleNamespace(returncode=0 if succeed else 1)

    monkeypatch.setattr(security.subprocess, "run", fake_icacls)


def test_windows_new_master_key_hardens_empty_file_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, Path]] = []
    _mock_windows_acl(monkeypatch, events, succeed=True)
    real_write = security._write_all
    real_fsync = security.os.fsync

    def observing_write(descriptor: int, payload: bytes) -> None:
        assert [event for event, _path in events] == ["acl"]
        events.append(("write", tmp_path / "master.key"))
        real_write(descriptor, payload)

    def observing_fsync(descriptor: int) -> None:
        assert [event for event, _path in events] == ["acl", "write"]
        events.append(("fsync", tmp_path / "master.key"))
        real_fsync(descriptor)

    monkeypatch.setattr(security, "_write_all", observing_write)
    monkeypatch.setattr(security.os, "fsync", observing_fsync)
    CredentialCipher(tmp_path / "master.key")

    assert [event for event, _path in events] == ["acl", "write", "fsync"]
    assert (tmp_path / "master.key").stat().st_size == 32


def test_windows_new_master_key_acl_failure_never_writes_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, Path]] = []
    _mock_windows_acl(monkeypatch, events, succeed=False)
    monkeypatch.setattr(
        security,
        "_write_all",
        lambda *_args: pytest.fail("key bytes must not be written before ACL success"),
    )

    with pytest.raises(RuntimeError, match="Windows ACL"):
        CredentialCipher(tmp_path / "master.key")

    assert [event for event, _path in events] == ["acl"]
    assert not (tmp_path / "master.key").exists()


def test_windows_master_key_rotation_hardens_temp_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "master.key"
    cipher = CredentialCipher(key_path)
    previous = key_path.read_bytes()
    events: list[tuple[str, Path]] = []
    _mock_windows_acl(monkeypatch, events, succeed=True)
    real_write = security._write_all

    def observing_write(descriptor: int, payload: bytes) -> None:
        assert [event for event, _path in events] == ["acl"]
        events.append(("write", events[0][1]))
        real_write(descriptor, payload)

    monkeypatch.setattr(security, "_write_all", observing_write)
    cipher.rotate()

    assert [event for event, _path in events] == ["acl", "write"]
    assert events[0][1].name.startswith(".master.key.")
    assert key_path.read_bytes() != previous
    assert list(tmp_path.glob(".master.key.*.tmp")) == []


def test_windows_master_key_rotation_acl_failure_preserves_old_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "master.key"
    cipher = CredentialCipher(key_path)
    previous = key_path.read_bytes()
    events: list[tuple[str, Path]] = []
    _mock_windows_acl(monkeypatch, events, succeed=False)
    monkeypatch.setattr(
        security,
        "_write_all",
        lambda *_args: pytest.fail("replacement key must not be written before ACL success"),
    )

    with pytest.raises(RuntimeError, match="Windows ACL"):
        cipher.rotate()

    assert key_path.read_bytes() == previous
    assert list(tmp_path.glob(".master.key.*.tmp")) == []


def test_windows_instance_file_hardens_empty_temp_before_token_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, Path]] = []
    _mock_windows_acl(monkeypatch, events, succeed=True)
    real_write = security._write_all

    def observing_write(descriptor: int, payload: bytes) -> None:
        assert [event for event, _path in events] == ["acl"]
        events.append(("write", events[0][1]))
        real_write(descriptor, payload)

    monkeypatch.setattr(security, "_write_all", observing_write)
    instance_path = tmp_path / "instance.json"
    _write_instance_file(instance_path, port=8765, local_token="local-test-token")

    assert [event for event, _path in events] == ["acl", "write"]
    assert events[0][1].name.startswith(".instance.json.")
    assert json.loads(instance_path.read_text(encoding="utf-8"))["local_token"] == (
        "local-test-token"
    )


def test_windows_instance_acl_failure_never_writes_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, Path]] = []
    _mock_windows_acl(monkeypatch, events, succeed=False)
    monkeypatch.setattr(
        security,
        "_write_all",
        lambda *_args: pytest.fail("local token must not be written before ACL success"),
    )
    instance_path = tmp_path / "instance.json"

    with pytest.raises(RuntimeError, match="Windows ACL"):
        _write_instance_file(instance_path, port=8765, local_token="local-test-token")

    assert [event for event, _path in events] == ["acl"]
    assert not instance_path.exists()
    assert list(tmp_path.glob(".instance.json.*.tmp")) == []


def test_instance_atomic_replace_rejects_symlink_target(tmp_path: Path) -> None:
    actual = tmp_path / "actual.json"
    actual.write_text("sentinel", encoding="utf-8")
    instance_path = tmp_path / "instance.json"
    try:
        instance_path.symlink_to(actual)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(RuntimeError, match="符号链接"):
        _write_instance_file(instance_path, port=8765, local_token="local-test-token")

    assert actual.read_text(encoding="utf-8") == "sentinel"


def test_instance_atomic_replace_detects_changed_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance_path = tmp_path / "instance.json"
    instance_path.write_text("old-instance", encoding="utf-8")
    original_writer = security.write_private_file

    def replace_target_during_write(path: str | Path, payload: bytes) -> os.stat_result:
        created = original_writer(path, payload)
        instance_path.unlink()
        instance_path.write_text("replacement", encoding="utf-8")
        return created

    monkeypatch.setattr(security, "write_private_file", replace_target_during_write)

    with pytest.raises(RuntimeError, match="替换前已变化"):
        _write_instance_file(instance_path, port=8765, local_token="local-test-token")

    assert instance_path.read_text(encoding="utf-8") == "replacement"
    assert list(tmp_path.glob(".instance.json.*.tmp")) == []
