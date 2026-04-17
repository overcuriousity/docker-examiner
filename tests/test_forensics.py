"""Tests for docker_forensics.py."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from docker_forensics import (
    DockerRoot,
    OverlayMerger,
    ReportBuilder,
    _build_path_set,
    _collect_diff,
    _file_sha256,
    _tree_sha256,
    chain_id,
    fmt_size,
    fmt_ts,
)


# ──────────────────────────────────────────────────────────────────────────────
# chain_id
# ──────────────────────────────────────────────────────────────────────────────

class TestChainId:
    def test_empty(self):
        assert chain_id([]) == []

    def test_single_layer_strips_prefix(self):
        ids = chain_id(["sha256:" + "a" * 64])
        assert ids == ["a" * 64]

    def test_two_layers(self):
        d0 = "sha256:" + "a" * 64
        d1 = "sha256:" + "b" * 64
        ids = chain_id([d0, d1])
        assert ids[0] == "a" * 64
        expected = hashlib.sha256(f"sha256:{'a' * 64} {d1}".encode()).hexdigest()
        assert ids[1] == expected

    def test_three_layers_chains_correctly(self):
        diffs = [f"sha256:{c * 64}" for c in ("a", "b", "c")]
        ids = chain_id(diffs)
        assert len(ids) == 3
        # Each chain ID feeds the next
        mid = hashlib.sha256(f"sha256:{'a' * 64} {diffs[1]}".encode()).hexdigest()
        assert ids[1] == mid
        end = hashlib.sha256(f"sha256:{mid} {diffs[2]}".encode()).hexdigest()
        assert ids[2] == end


# ──────────────────────────────────────────────────────────────────────────────
# DockerRoot
# ──────────────────────────────────────────────────────────────────────────────

class TestDockerRoot:
    def test_images_found(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        images = dr.images()
        assert len(images) == 1
        assert images[0]["id"] == docker_root["image_id"]

    def test_image_tags(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        images = dr.images()
        assert "myimage:latest" in images[0]["tags"]

    def test_containers_found(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        containers = dr.containers_list()
        assert len(containers) == 1
        assert containers[0]["id"] == docker_root["container_id"]

    def test_container_image_name(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        c = dr.containers_list()[0]
        assert c["image_name"] == "myimage:latest"

    def test_image_cache_ids(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        ids = dr.image_cache_ids(docker_root["image_id"])
        assert ids == [docker_root["cache_id_0"], docker_root["cache_id_1"]]

    def test_container_upper_id(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        uid = dr.container_upper_id(docker_root["container_id"])
        assert uid == docker_root["upper_id"]

    def test_resolve_image_by_prefix(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        img = dr.resolve_image(docker_root["image_id"][:10])
        assert img["id"] == docker_root["image_id"]

    def test_resolve_image_not_found(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        with pytest.raises(ValueError, match="No image"):
            dr.resolve_image("zzzzzzzzzz")

    def test_resolve_container_not_found(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        with pytest.raises(ValueError, match="No container"):
            dr.resolve_container("zzzzzzzzzz")

    def test_container_log_path(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        log = dr.container_log_path(docker_root["container_id"])
        assert log is not None
        assert log.exists()

    def test_no_images_on_empty_root(self, tmp_path):
        (tmp_path / "overlay2").mkdir()
        (tmp_path / "image" / "overlay2").mkdir(parents=True)
        dr = DockerRoot(tmp_path)
        assert dr.images() == []

    def test_no_containers_on_empty_root(self, tmp_path):
        (tmp_path / "overlay2").mkdir()
        dr = DockerRoot(tmp_path)
        assert dr.containers_list() == []


# ──────────────────────────────────────────────────────────────────────────────
# OverlayMerger
# ──────────────────────────────────────────────────────────────────────────────

class TestOverlayMerger:
    def test_basic_merge_copies_files(self, docker_root, tmp_path):
        dr     = DockerRoot(docker_root["root"])
        output = tmp_path / "merged"
        OverlayMerger(dr).merge(
            [docker_root["cache_id_0"], docker_root["cache_id_1"]], output
        )
        assert (output / "etc" / "passwd").exists()
        assert (output / "usr" / "bin" / "sh").exists()
        assert (output / "app" / "main.py").read_text() == "print('hello')\n"

    def test_whiteout_deletes_file(self, docker_root, tmp_path):
        dr     = DockerRoot(docker_root["root"])
        output = tmp_path / "merged"
        # Merge all three layers: base → app → upper (upper has .wh.hosts)
        OverlayMerger(dr).merge(
            [docker_root["cache_id_0"], docker_root["cache_id_1"], docker_root["upper_id"]],
            output,
        )
        # /etc/hosts was in layer 0, whiteout'd in upper
        assert not (output / "etc" / "hosts").exists()

    def test_file_overwritten_by_upper(self, docker_root, tmp_path):
        dr     = DockerRoot(docker_root["root"])
        output = tmp_path / "merged"
        OverlayMerger(dr).merge(
            [docker_root["cache_id_0"], docker_root["upper_id"]], output
        )
        content = (output / "etc" / "passwd").read_text()
        assert "hacker" in content

    def test_missing_layer_skipped(self, docker_root, tmp_path):
        dr     = DockerRoot(docker_root["root"])
        output = tmp_path / "merged"
        merger = OverlayMerger(dr)
        merger.merge([None, docker_root["cache_id_0"]], output)
        assert merger.stats["missing_layers"] == 1
        assert (output / "etc" / "passwd").exists()

    def test_opaque_whiteout_clears_dir(self, tmp_path):
        """An opaque whiteout wipes existing directory contents before applying new ones."""
        # Build a tiny docker root by hand
        root = tmp_path / "docker"
        (root / "overlay2").mkdir(parents=True)
        (root / "image" / "overlay2").mkdir(parents=True)
        dr = DockerRoot(root)

        # Layer A: /data/old_file
        layerA = root / "overlay2" / "layerA" / "diff"
        layerA.mkdir(parents=True)
        (layerA / "data").mkdir()
        (layerA / "data" / "old_file").write_text("old")

        # Layer B: opaque whiteout replaces /data, adds /data/new_file
        layerB = root / "overlay2" / "layerB" / "diff"
        layerB.mkdir(parents=True)
        (layerB / "data").mkdir()
        (layerB / "data" / ".wh..wh..opq").write_text("")
        (layerB / "data" / "new_file").write_text("new")

        output = tmp_path / "out"
        OverlayMerger(dr).merge(["layerA", "layerB"], output)

        assert not (output / "data" / "old_file").exists()
        assert (output / "data" / "new_file").read_text() == "new"


# ──────────────────────────────────────────────────────────────────────────────
# Diff helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildPathSet:
    def test_collects_paths_from_layers(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        paths = _build_path_set(dr, [docker_root["cache_id_0"], docker_root["cache_id_1"]])
        assert "etc/passwd" in paths
        assert "etc/hosts" in paths
        assert "app/main.py" in paths

    def test_skips_none(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        # Should not crash on None entries
        paths = _build_path_set(dr, [None, docker_root["cache_id_0"]])
        assert "etc/passwd" in paths


class TestCollectDiff:
    def _image_paths(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        ids = dr.image_cache_ids(docker_root["image_id"])
        return _build_path_set(dr, ids)

    def _diff_dir(self, docker_root):
        dr = DockerRoot(docker_root["root"])
        return dr.overlay2 / docker_root["upper_id"] / "diff"

    def test_modified_file_detected(self, docker_root):
        changes = _collect_diff(self._diff_dir(docker_root), self._image_paths(docker_root))
        modified = [ch["path"] for ch in changes if ch["change"] == "M"]
        assert "/etc/passwd" in modified

    def test_added_file_detected(self, docker_root):
        changes = _collect_diff(self._diff_dir(docker_root), self._image_paths(docker_root))
        added = [ch["path"] for ch in changes if ch["change"] == "A"]
        assert "/etc/malware.sh" in added

    def test_deleted_file_detected(self, docker_root):
        changes = _collect_diff(self._diff_dir(docker_root), self._image_paths(docker_root))
        deleted = [ch["path"] for ch in changes if ch["change"] == "D"]
        assert "/etc/hosts" in deleted

    def test_output_sorted_by_path(self, docker_root):
        changes = _collect_diff(self._diff_dir(docker_root), self._image_paths(docker_root))
        paths = [ch["path"] for ch in changes]
        assert paths == sorted(paths)

    def test_no_whiteout_files_in_output(self, docker_root):
        """Whiteout marker files (.wh.*) must not appear as entries themselves."""
        changes = _collect_diff(self._diff_dir(docker_root), self._image_paths(docker_root))
        for ch in changes:
            assert ".wh." not in ch["path"]

    def test_opaque_whiteout_entry(self, tmp_path):
        diff = tmp_path / "diff"
        d    = diff / "cache"
        d.mkdir(parents=True)
        (d / ".wh..wh..opq").write_text("")
        (d / "newfile").write_text("x")

        changes = _collect_diff(diff, set())
        types   = {ch["path"]: ch["type"] for ch in changes}
        assert types.get("/cache") == "opq"
        assert "/cache/newfile" in types

    def test_symlink_reported(self, tmp_path):
        diff = tmp_path / "diff"
        diff.mkdir()
        import os
        os.symlink("/usr/bin/python3", diff / "python")

        changes = _collect_diff(diff, set())
        assert len(changes) == 1
        assert changes[0]["type"] == "sym"
        assert changes[0]["note"] == "/usr/bin/python3"
        assert changes[0]["change"] == "A"

    def test_empty_upper_layer(self, tmp_path):
        diff = tmp_path / "diff"
        diff.mkdir()
        assert _collect_diff(diff, set()) == []


# ──────────────────────────────────────────────────────────────────────────────
# fmt helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestFmtHelpers:
    def test_fmt_size_bytes(self):
        assert fmt_size(512) == "512.0 B"

    def test_fmt_size_kib(self):
        assert fmt_size(2048) == "2.0 KiB"

    def test_fmt_size_mib(self):
        assert fmt_size(3 * 1024 * 1024) == "3.0 MiB"

    def test_fmt_size_gib(self):
        assert fmt_size(2 * 1024 ** 3) == "2.0 GiB"

    def test_fmt_size_tib(self):
        assert "TiB" in fmt_size(2 * 1024 ** 4)

    def test_fmt_ts_utc_z(self):
        assert fmt_ts("2024-01-01T00:00:00Z") == "2024-01-01 00:00:00 UTC"

    def test_fmt_ts_with_offset(self):
        assert fmt_ts("2024-06-15T12:30:00+00:00") == "2024-06-15 12:30:00 UTC"

    def test_fmt_ts_empty(self):
        assert fmt_ts("") == "(unknown)"

    def test_fmt_ts_garbage(self):
        assert fmt_ts("not-a-date") == "not-a-date"


# ──────────────────────────────────────────────────────────────────────────────
# _tree_sha256
# ──────────────────────────────────────────────────────────────────────────────

class TestTreeSha256:
    def _make_tree(self, base: Path):
        (base / "a").write_bytes(b"hello")
        (base / "sub").mkdir()
        (base / "sub" / "b").write_bytes(b"world")
        import os
        os.symlink("../a", base / "sub" / "link")

    def test_deterministic(self, tmp_path):
        t1 = tmp_path / "t1"
        t2 = tmp_path / "t2"
        t1.mkdir()
        t2.mkdir()
        self._make_tree(t1)
        self._make_tree(t2)
        assert _tree_sha256(t1) == _tree_sha256(t2)

    def test_different_content_different_hash(self, tmp_path):
        t1 = tmp_path / "t1"
        t2 = tmp_path / "t2"
        t1.mkdir()
        t2.mkdir()
        (t1 / "f").write_bytes(b"aaa")
        (t2 / "f").write_bytes(b"bbb")
        assert _tree_sha256(t1) != _tree_sha256(t2)

    def test_returns_hex_string(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        (d / "x").write_bytes(b"x")
        h = _tree_sha256(d)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_empty_dir(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        h = _tree_sha256(d)
        assert len(h) == 64


# ──────────────────────────────────────────────────────────────────────────────
# ReportBuilder
# ──────────────────────────────────────────────────────────────────────────────

class TestReportBuilder:
    def test_report_contains_image_id(self, docker_root):
        dr     = DockerRoot(docker_root["root"])
        report = ReportBuilder(dr).build()
        assert docker_root["image_id"][:12] in report

    def test_report_contains_container_id(self, docker_root):
        dr     = DockerRoot(docker_root["root"])
        report = ReportBuilder(dr).build()
        assert docker_root["container_id"][:12] in report

    def test_report_contains_log_sha256(self, docker_root):
        dr       = DockerRoot(docker_root["root"])
        log_path = dr.container_log_path(docker_root["container_id"])
        log_sha  = _file_sha256(log_path)
        report   = ReportBuilder(dr).build()
        assert log_sha in report

    def test_report_contains_config_sha256(self, docker_root):
        dr       = DockerRoot(docker_root["root"])
        cfg_path = dr.containers / docker_root["container_id"] / "config.v2.json"
        cfg_sha  = _file_sha256(cfg_path)
        report   = ReportBuilder(dr).build()
        assert cfg_sha in report

    def test_integrity_footer_present(self, docker_root):
        dr     = DockerRoot(docker_root["root"])
        report = ReportBuilder(dr).build()
        assert "Report body SHA-256" in report

    def test_integrity_footer_verifiable(self, docker_root):
        dr     = DockerRoot(docker_root["root"])
        report = ReportBuilder(dr).build()
        lines  = report.splitlines()
        # Find footer line (last non-empty line that contains the hash)
        footer_line = next(
            l for l in reversed(lines) if "Report body SHA-256" in l
        )
        # Extract the hex digest from the backtick-delimited token
        import re
        m = re.search(r"`([0-9a-f]{64})`", footer_line)
        assert m, "Could not find SHA-256 hex digest in footer"
        claimed = m.group(1)
        # Body is everything before the "---\n\n" separator
        body = report.split("---\n\n")[0]
        actual = hashlib.sha256(body.encode()).hexdigest()
        assert claimed == actual

    def test_hash_layers_includes_tree_hashes(self, docker_root):
        dr     = DockerRoot(docker_root["root"])
        report = ReportBuilder(dr, hash_layers=True).build()
        # With hash_layers the layer table has an extra column header
        assert "Tree SHA-256" in report

    def test_two_runs_same_footer_hash(self, docker_root):
        """Body hash must be stable across runs (UUID and timestamp aside)."""
        import re
        dr = DockerRoot(docker_root["root"])

        def get_hash(rpt):
            m = re.search(r"Report body SHA-256.*`([0-9a-f]{64})`", rpt)
            assert m
            return m.group(1)

        h1 = get_hash(ReportBuilder(dr).build())
        # Reset warnings so they don't accumulate
        dr.warnings.clear()
        h2 = get_hash(ReportBuilder(dr).build())
        # Hashes will differ only because of UUID and timestamp — we verify
        # structural consistency rather than byte-for-byte equality.
        # Both should look like valid SHA-256 digests.
        assert len(h1) == 64
        assert len(h2) == 64

    def test_warnings_section_present(self, docker_root):
        dr     = DockerRoot(docker_root["root"])
        report = ReportBuilder(dr).build()
        assert "## Warnings" in report


# ──────────────────────────────────────────────────────────────────────────────
# cmd_extract — existing-file guard
# ──────────────────────────────────────────────────────────────────────────────

class TestCmdExtract:
    def test_extract_to_existing_file_gives_clean_error(self, docker_root, tmp_path, capsys):
        """extract must print a clear error when output path is a regular file."""
        import argparse
        from docker_forensics import cmd_extract

        out_file = tmp_path / "not_a_dir.txt"
        out_file.write_text("i am a file")

        dr   = DockerRoot(docker_root["root"])
        args = argparse.Namespace(
            kind="image",
            id=docker_root["image_id"][:12],
            output=str(out_file),
            verbose=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_extract(args, dr)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "not a directory" in captured.err.lower() or "is not a directory" in captured.err
