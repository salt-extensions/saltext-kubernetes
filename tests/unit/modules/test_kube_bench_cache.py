"""
Unit tests for the ``kube_bench_cache`` execution module.

Covers the pure/mockable logic -- section parsing, pillar/kwarg
precedence, connection kwarg translation, freshness/atomic-write
helpers, and ``status_for_check``'s per-node aggregation -- without
bringing up a cluster. Job-orchestration functions
(``_collect_job``/``_wait_for_job``/``_create_assessment_job``) are
integration-shaped (poll loops, multi-call sequencing against
``kubernetes.*``) and are intentionally left to functional/integration
tests against a real or ``kind`` cluster.
"""

import json
import os
import time
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from saltext.kubernetes.modules import kube_bench_cache


@pytest.fixture
def configure_loader_modules():
    return {
        kube_bench_cache: {
            "__salt__": {},
            "__pillar__": {},
            "__opts__": {},
        }
    }


# ---------------------------------------------------------------------------
# _parse_sections
# ---------------------------------------------------------------------------


def test_parse_sections_single_document():
    doc = {"id": "1", "tests": []}
    assert kube_bench_cache._parse_sections(json.dumps(doc)) == [doc]


def test_parse_sections_multiple_concatenated_documents():
    doc1 = {"id": "1", "tests": []}
    doc2 = {"id": "2", "tests": []}
    raw = json.dumps(doc1) + "\n" + json.dumps(doc2)
    assert kube_bench_cache._parse_sections(raw) == [doc1, doc2]


def test_parse_sections_controls_envelope():
    controls = [{"id": "1"}, {"id": "2"}]
    raw = json.dumps({"Controls": controls, "Totals": {"pass": 2}})
    assert kube_bench_cache._parse_sections(raw) == controls


def test_parse_sections_skips_non_json_noise():
    doc = {"id": "1", "tests": []}
    raw = "entrypoint: some warning\n" + json.dumps(doc) + "\ntrailing noise"
    assert kube_bench_cache._parse_sections(raw) == [doc]


def test_parse_sections_ignores_documents_without_id_or_controls():
    raw = json.dumps({"Totals": {"pass": 2}})
    assert not kube_bench_cache._parse_sections(raw)


def test_parse_sections_empty_input_returns_empty_list():
    assert not kube_bench_cache._parse_sections("")
    assert not kube_bench_cache._parse_sections("   ")


# ---------------------------------------------------------------------------
# _label_matches
# ---------------------------------------------------------------------------


def test_label_matches_all_clauses_satisfied():
    labels = {"app": "kube-bench", "tier": "cache"}
    assert kube_bench_cache._label_matches(labels, "app=kube-bench,tier=cache")


def test_label_matches_fails_on_mismatched_value():
    assert not kube_bench_cache._label_matches({"app": "other"}, "app=kube-bench")


def test_label_matches_treats_missing_labels_as_empty():
    assert not kube_bench_cache._label_matches(None, "app=kube-bench")


# ---------------------------------------------------------------------------
# _conn_kwargs
# ---------------------------------------------------------------------------


def test_conn_kwargs_defaults_to_empty_dict():
    assert not kube_bench_cache._conn_kwargs(None, None)


def test_conn_kwargs_passes_through_kubeconfig_when_auth_mode_unset():
    assert kube_bench_cache._conn_kwargs(None, "/path/to/kubeconfig") == {
        "kubeconfig": "/path/to/kubeconfig"
    }


def test_conn_kwargs_in_cluster_ignores_kubeconfig():
    assert kube_bench_cache._conn_kwargs("in_cluster", "/path/to/kubeconfig") == {
        "in_cluster": True
    }


def test_conn_kwargs_kubeconfig_mode_requires_kubeconfig():
    with pytest.raises(RuntimeError):
        kube_bench_cache._conn_kwargs("kubeconfig", None)


def test_conn_kwargs_kubeconfig_mode_returns_kubeconfig():
    assert kube_bench_cache._conn_kwargs("kubeconfig", "/path") == {"kubeconfig": "/path"}


def test_conn_kwargs_unknown_auth_mode_falls_back_to_default_resolution():
    assert kube_bench_cache._conn_kwargs("bogus", "/path") == {"kubeconfig": "/path"}


# ---------------------------------------------------------------------------
# _pillar_cfg
# ---------------------------------------------------------------------------


def test_pillar_cfg_prefers_pillar_get():
    with patch.dict(
        kube_bench_cache.__salt__,
        {"pillar.get": MagicMock(return_value={"namespace": "from-pillar-get"})},
    ):
        with patch.dict(kube_bench_cache.__pillar__, {"kube_bench": {"namespace": "from-dunder"}}):
            assert kube_bench_cache._pillar_cfg() == {"namespace": "from-pillar-get"}


def test_pillar_cfg_falls_back_to_pillar_dunder_when_pillar_get_empty():
    with patch.dict(kube_bench_cache.__salt__, {"pillar.get": MagicMock(return_value={})}):
        with patch.dict(kube_bench_cache.__pillar__, {"kube_bench": {"namespace": "from-dunder"}}):
            assert kube_bench_cache._pillar_cfg() == {"namespace": "from-dunder"}


def test_pillar_cfg_falls_back_to_opts_when_pillar_sources_empty():
    with patch.dict(kube_bench_cache.__salt__, {"pillar.get": MagicMock(return_value={})}):
        with patch.dict(kube_bench_cache.__opts__, {"kube_bench": {"namespace": "from-opts"}}):
            assert kube_bench_cache._pillar_cfg() == {"namespace": "from-opts"}


def test_pillar_cfg_survives_pillar_get_raising():
    with patch.dict(
        kube_bench_cache.__salt__,
        {"pillar.get": MagicMock(side_effect=KeyError("no pillar.get"))},
    ):
        with patch.dict(kube_bench_cache.__opts__, {"kube_bench": {"namespace": "from-opts"}}):
            assert kube_bench_cache._pillar_cfg() == {"namespace": "from-opts"}


def test_pillar_cfg_returns_empty_dict_when_all_sources_empty():
    assert kube_bench_cache._pillar_cfg() == {}


# ---------------------------------------------------------------------------
# _is_fresh
# ---------------------------------------------------------------------------


def test_is_fresh_returns_false_when_file_missing(tmp_path):
    assert kube_bench_cache._is_fresh(str(tmp_path / "missing.json"), 900) is False


def test_is_fresh_returns_true_within_ttl(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("[]")
    assert kube_bench_cache._is_fresh(str(cache_file), 900) is True


def test_is_fresh_returns_false_when_stale(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("[]")
    stale_time = time.time() - 1000
    os.utime(cache_file, (stale_time, stale_time))
    assert kube_bench_cache._is_fresh(str(cache_file), 900) is False


# ---------------------------------------------------------------------------
# _write_atomic
# ---------------------------------------------------------------------------


def test_write_atomic_writes_json_and_cleans_up_tmp_file(tmp_path):
    cache_file = tmp_path / "cache.json"
    sections = [{"id": "1"}]
    kube_bench_cache._write_atomic(str(cache_file), sections)
    assert json.loads(cache_file.read_text()) == sections
    assert not (tmp_path / "cache.json.tmp").exists()


# ---------------------------------------------------------------------------
# _format_node_result / status_for_check
# ---------------------------------------------------------------------------


def test_format_node_result_falls_back_to_reason_when_actual_value_blank():
    result = {
        "status": "FAIL",
        "actual_value": "",
        "reason": "no such file or directory",
        "expected_result": "",
    }
    assert (
        kube_bench_cache._format_node_result("node-a", result)
        == "node-a: FAIL actual=no such file or directory"
    )


def test_format_node_result_includes_expected_when_present():
    result = {"status": "FAIL", "actual_value": "3", "expected_result": "eq 2"}
    assert (
        kube_bench_cache._format_node_result("node-a", result)
        == "node-a: FAIL expected=eq 2 actual=3"
    )


def test_format_node_result_defaults_node_name_when_missing():
    line = kube_bench_cache._format_node_result(None, {"status": "PASS", "actual_value": "ok"})
    assert line.startswith("unknown-node:")


def _section(node_name, test_number, status, **result_extra):
    result = {"test_number": test_number, "status": status}
    result.update(result_extra)
    return {"node_name": node_name, "tests": [{"results": [result]}]}


def _write_cache(tmp_path, sections):
    cache_file = tmp_path / "kube-bench.json"
    cache_file.write_text(json.dumps(sections))
    return str(cache_file)


def test_status_for_check_returns_error_when_control_not_found(tmp_path, monkeypatch):
    cache_path = _write_cache(tmp_path, [_section("node-a", "1.1.1", "PASS")])
    monkeypatch.setattr(kube_bench_cache, "ensure_fresh", MagicMock(return_value=cache_path))
    result = kube_bench_cache.status_for_check("9.9.9")
    assert result["status"] == "ERROR"
    assert "9.9.9" in result["comment"]


def test_status_for_check_all_pass(tmp_path, monkeypatch):
    sections = [
        _section("node-a", "1.1.1", "PASS", actual_value="ok"),
        _section("node-b", "1.1.1", "PASS", actual_value="ok"),
    ]
    cache_path = _write_cache(tmp_path, sections)
    monkeypatch.setattr(kube_bench_cache, "ensure_fresh", MagicMock(return_value=cache_path))
    result = kube_bench_cache.status_for_check("1.1.1")
    assert result["status"] == "PASS"
    assert "node-a: PASS" in result["comment"]
    assert "node-b: PASS" in result["comment"]


def test_status_for_check_fail_wins_over_pass(tmp_path, monkeypatch):
    sections = [
        _section("node-a", "1.1.1", "PASS", actual_value="ok"),
        _section("node-b", "1.1.1", "FAIL", actual_value="bad"),
    ]
    cache_path = _write_cache(tmp_path, sections)
    monkeypatch.setattr(kube_bench_cache, "ensure_fresh", MagicMock(return_value=cache_path))
    result = kube_bench_cache.status_for_check("1.1.1")
    assert result["status"] == "FAIL"


def test_status_for_check_warn_when_no_fail_present(tmp_path, monkeypatch):
    sections = [
        _section("node-a", "1.1.1", "PASS", actual_value="ok"),
        _section("node-b", "1.1.1", "WARN", actual_value="check manually"),
    ]
    cache_path = _write_cache(tmp_path, sections)
    monkeypatch.setattr(kube_bench_cache, "ensure_fresh", MagicMock(return_value=cache_path))
    result = kube_bench_cache.status_for_check("1.1.1")
    assert result["status"] == "WARN"
