import copy
import json

import pytest

from conftest import baseline_dict
from filesift import integrity
from filesift.baseline import build_baseline_dict, load_baseline, serialize_baseline
from filesift.errors import BaselineAuthError, ConfigError
from filesift.scanner import Inventory

KEY = b"k" * 32
OTHER_KEY = b"o" * 32


def _signed(key=KEY):
    d = baseline_dict()
    integrity.sign(d, key)
    return d


def _write(tmp_path, obj, **dump_kwargs):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(obj, **dump_kwargs), encoding="utf-8")
    return path


def test_load_key_unset(monkeypatch):
    monkeypatch.delenv("FILESIFT_KEY", raising=False)
    assert integrity.load_key() is None


@pytest.mark.parametrize("value", ["", "short", "x" * 31, "é" * 15])
def test_short_key_is_config_error(monkeypatch, value):
    monkeypatch.setenv("FILESIFT_KEY", value)
    with pytest.raises(ConfigError) as exc:
        integrity.load_key()
    assert exc.value.exit_code == 2


@pytest.mark.parametrize("value", ["x" * 32, "é" * 16])
def test_key_length_counts_utf8_bytes(monkeypatch, value):
    monkeypatch.setenv("FILESIFT_KEY", value)
    assert integrity.load_key() == value.encode("utf-8")


def test_sign_sets_integrity_last():
    d = _signed()
    assert d["integrity"]["algorithm"] == "hmac-sha256"
    assert len(d["integrity"]["mac"]) == 64
    assert integrity.verify(copy.deepcopy(d), KEY) is True


def test_signature_ignores_previous_integrity_value():
    d = baseline_dict()
    d["integrity"] = {"algorithm": "hmac-sha256", "mac": "f" * 64}
    integrity.sign(d, KEY)
    assert d["integrity"] == _signed()["integrity"]


def test_tamper_detected(tmp_path):
    d = _signed()
    d["entries"]["a.txt"]["sha256"] = "c" * 64
    with pytest.raises(BaselineAuthError):
        load_baseline(_write(tmp_path, d), KEY)


def test_wrong_key_detected(tmp_path):
    with pytest.raises(BaselineAuthError):
        load_baseline(_write(tmp_path, _signed()), OTHER_KEY)


@pytest.mark.parametrize("dump_kwargs", [
    {"indent": 2, "sort_keys": True},
    {"separators": (",", ":")},
    {"indent": 7, "ensure_ascii": False},
])
def test_canonicalization_ignores_whitespace_and_key_order(tmp_path, dump_kwargs):
    d = _signed()
    reordered = dict(reversed(list(d.items())))
    _, _, authenticated = load_baseline(_write(tmp_path, reordered, **dump_kwargs), KEY)
    assert authenticated is True


def test_matrix_mac_and_key_verifies(tmp_path):
    _, _, authenticated = load_baseline(_write(tmp_path, _signed()), KEY)
    assert authenticated is True


def test_matrix_mac_without_key_rejected(tmp_path):
    with pytest.raises(BaselineAuthError, match="not set") as exc:
        load_baseline(_write(tmp_path, _signed()), None)
    assert exc.value.exit_code == 3


def test_matrix_key_without_mac_rejected_as_downgrade(tmp_path):
    with pytest.raises(BaselineAuthError, match="downgrade"):
        load_baseline(_write(tmp_path, baseline_dict()), KEY)


def test_matrix_no_mac_no_key_unauthenticated(tmp_path):
    _, _, authenticated = load_baseline(_write(tmp_path, baseline_dict()), None)
    assert authenticated is False


def test_built_baseline_is_signed_and_loadable(tmp_path):
    doc = build_baseline_dict(tmp_path.resolve(), Inventory(), (), KEY)
    path = tmp_path / "baseline.json"
    path.write_bytes(serialize_baseline(doc))
    loaded, _, authenticated = load_baseline(path, KEY)
    assert authenticated is True
    assert loaded.integrity.mac == doc["integrity"]["mac"]
