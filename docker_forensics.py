#!/usr/bin/env python3
"""
docker_forensics.py — Reassemble and inspect Docker filesystems from forensic images.

Supports Docker's overlay2 storage driver (default since Docker 1.13).

Usage:
  docker_forensics.py <docker-root> list [--json]
  docker_forensics.py <docker-root> inspect (image|container) <id-prefix> [--json]
  docker_forensics.py <docker-root> layers (image|container) <id-prefix> [--json]
  docker_forensics.py <docker-root> diff container <id-prefix> [--json]
  docker_forensics.py <docker-root> log <id-prefix> [--json] [--stdout] [--stderr]
  docker_forensics.py <docker-root> extract (image|container) <id-prefix> <output-dir> [-v]

<docker-root> is the path to the Docker data directory on your analysis machine,
e.g. /mnt/evidence/var/lib/docker  or  /cases/001/docker
"""

import argparse
import getpass
import hashlib
import io
import json
import os
import platform
import shutil
import socket
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def short(sha: str, n: int = 12) -> str:
    return sha[:n]


def fmt_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def fmt_ts(ts: str) -> str:
    """Format an ISO-8601 timestamp into a human-readable string."""
    if not ts:
        return "(unknown)"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return ts


def chain_id(diff_ids: list[str]) -> list[str]:
    """
    Compute the overlay2 chain IDs from a list of diff IDs.
    chain_id[0] = diff_ids[0] (strip "sha256:" prefix)
    chain_id[i] = sha256("sha256:<chain_id[i-1]> <diff_ids[i]>")
    """
    result: list[str] = []
    for i, did in enumerate(diff_ids):
        raw = did.removeprefix("sha256:")
        if i == 0:
            result.append(raw)
        else:
            parent = result[-1]
            digest = hashlib.sha256(f"sha256:{parent} {did}".encode()).hexdigest()
            result.append(digest)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Docker layout reader
# ──────────────────────────────────────────────────────────────────────────────

class DockerRoot:
    """Wraps a (possibly offline) Docker data directory."""

    def __init__(self, root: Path):
        # Accept both the raw mount and a path that already ends in var/lib/docker
        for candidate in [root, root / "var" / "lib" / "docker", root / "lib" / "docker"]:
            if (candidate / "overlay2").exists() or (candidate / "image").exists():
                self.root = candidate
                break
        else:
            self.root = root  # best effort

        self.overlay2    = self.root / "overlay2"
        self.image_db    = self.root / "image" / "overlay2"
        self.containers  = self.root / "containers"
        self.warnings: list[str] = []

    # ── Image enumeration ────────────────────────────────────────────────────

    def images(self) -> list[dict]:
        img_dir = self.image_db / "imagedb" / "content" / "sha256"
        try:
            entries = sorted(img_dir.iterdir())
        except PermissionError:
            print(f"[!] Permission denied: {img_dir} — re-run as root / with sudo", file=sys.stderr)
            return []
        except FileNotFoundError:
            return []
        tags_map = self.image_tags()
        result = []
        for p in entries:
            try:
                cfg = json.loads(p.read_text())
                result.append({"id": p.name, "config": cfg,
                                "tags": tags_map.get(p.name, [])})
            except Exception as exc:
                msg = f"[!] skipped image {p.name[:12]}: {exc}"
                print(msg, file=sys.stderr)
                self.warnings.append(msg)
        return result

    def resolve_image(self, prefix: str) -> dict:
        matches = [i for i in self.images() if i["id"].startswith(prefix)]
        if not matches:
            raise ValueError(f"No image matching '{prefix}'")
        if len(matches) > 1:
            raise ValueError(f"Ambiguous prefix '{prefix}': {[short(m['id']) for m in matches]}")
        return matches[0]

    # ── Container enumeration ────────────────────────────────────────────────

    def containers_list(self) -> list[dict]:
        try:
            entries = sorted(self.containers.iterdir())
        except PermissionError:
            print(f"[!] Permission denied: {self.containers} — re-run as root / with sudo", file=sys.stderr)
            return []
        except FileNotFoundError:
            return []
        tags_map = self.image_tags()
        result = []
        for p in entries:
            cfg_path = p / "config.v2.json"
            if cfg_path.exists():
                try:
                    cfg = json.loads(cfg_path.read_text())
                    run_image = cfg.get("Config", {}).get("Image", "")
                    if run_image and not run_image.startswith("sha256:"):
                        image_name = run_image
                    else:
                        img_id = cfg.get("Image", "").removeprefix("sha256:")
                        names  = tags_map.get(img_id, [])
                        image_name = names[0] if names else ""
                    result.append({"id": p.name, "config": cfg, "image_name": image_name})
                except Exception as exc:
                    msg = f"[!] skipped container {p.name[:12]}: {exc}"
                    print(msg, file=sys.stderr)
                    self.warnings.append(msg)
        return result

    def resolve_container(self, prefix: str) -> dict:
        matches = [c for c in self.containers_list() if c["id"].startswith(prefix)]
        if not matches:
            raise ValueError(f"No container matching '{prefix}'")
        if len(matches) > 1:
            raise ValueError(f"Ambiguous prefix '{prefix}': {[short(m['id']) for m in matches]}")
        return matches[0]

    # ── Layer resolution ─────────────────────────────────────────────────────

    def image_cache_ids(self, image_id: str) -> list[Optional[str]]:
        """Return overlay2 cache-IDs for an image's layers, bottom-to-top."""
        img_path = self.image_db / "imagedb" / "content" / "sha256" / image_id
        cfg = json.loads(img_path.read_text())
        diff_ids = cfg.get("rootfs", {}).get("diff_ids", [])
        if not diff_ids:
            return []

        cids = chain_id(diff_ids)
        cache_ids = []
        for cid in cids:
            cache_id_file = self.image_db / "layerdb" / "sha256" / cid / "cache-id"
            if cache_id_file.exists():
                cache_ids.append(cache_id_file.read_text().strip())
            else:
                cache_ids.append(None)
        return cache_ids

    def container_upper_id(self, container_id: str) -> Optional[str]:
        """Return the overlay2 cache-ID of the container's writable upper layer."""
        mount_id_file = self.image_db / "layerdb" / "mounts" / container_id / "mount-id"
        if mount_id_file.exists():
            return mount_id_file.read_text().strip()
        init_id_file = self.image_db / "layerdb" / "mounts" / container_id / "init-id"
        if init_id_file.exists():
            init_id = init_id_file.read_text().strip()
            upper = init_id.removesuffix("-init")
            if (self.overlay2 / upper).exists():
                return upper
        return None

    def container_init_id(self, container_id: str) -> Optional[str]:
        """Return the overlay2 cache-ID of the container's -init layer, if present.

        Docker injects /etc/hostname, /etc/hosts, /etc/resolv.conf, and empty
        /dev, /proc, /sys mount-point stubs into the init layer at container
        creation time.
        """
        init_id_file = self.image_db / "layerdb" / "mounts" / container_id / "init-id"
        if init_id_file.exists():
            return init_id_file.read_text().strip()
        mount_id_file = self.image_db / "layerdb" / "mounts" / container_id / "mount-id"
        if mount_id_file.exists():
            candidate = mount_id_file.read_text().strip() + "-init"
            if (self.overlay2 / candidate).exists():
                return candidate
        return None

    def image_tags(self) -> dict[str, list[str]]:
        """Read repositories.json → image_id → [tag, …]."""
        repo_file = self.image_db / "repositories.json"
        if not repo_file.exists():
            return {}
        try:
            data = json.loads(repo_file.read_text())
        except Exception:
            return {}
        result: dict[str, list[str]] = {}
        for _repo, tags in data.get("Repositories", {}).items():
            for tag, full_id in tags.items():
                img_id = full_id.removeprefix("sha256:")
                result.setdefault(img_id, []).append(tag)
        return result

    def layer_diff_dir(self, cache_id: str) -> Optional[Path]:
        d = self.overlay2 / cache_id / "diff"
        return d if d.exists() else None

    def container_log_path(self, container_id: str) -> Optional[Path]:
        """Return the path to the container's JSON log file, if present."""
        ctr_dir = self.containers / container_id
        # Standard location: containers/<id>/<id>-json.log
        candidate = ctr_dir / f"{container_id}-json.log"
        if candidate.exists():
            return candidate
        # Some setups use a symlink or alternate name
        for p in ctr_dir.glob("*.log"):
            return p
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Overlay merge
# ──────────────────────────────────────────────────────────────────────────────

class OverlayMerger:
    """
    Applies overlay2 layers onto an output directory, respecting:
      - Normal files / directories   → copy/overwrite
      - .wh.<name>                   → delete <name> in output
      - .wh..wh..opq                 → opaque dir: wipe dir contents before applying
    """

    def __init__(self, docker: DockerRoot, verbose: bool = False):
        self.docker = docker
        self.verbose = verbose
        self.stats = {
            "added": 0, "overwritten": 0, "deleted": 0, "missing_layers": 0,
            "special": 0, "special_skipped": 0,
        }

    def merge(self, cache_ids: list[Optional[str]], output: Path):
        output.mkdir(parents=True, exist_ok=True)
        for cache_id in cache_ids:
            if cache_id is None:
                self.stats["missing_layers"] += 1
                print(f"  [!] Layer not found on disk (skipped)", file=sys.stderr)
                continue
            diff = self.docker.layer_diff_dir(cache_id)
            if diff is None:
                self.stats["missing_layers"] += 1
                print(f"  [!] diff/ missing for layer {short(cache_id)} (skipped)", file=sys.stderr)
                continue
            if self.verbose:
                print(f"  Applying layer {short(cache_id)} …")
            self._apply_layer(diff, output)

        skipped_note = (
            f", {self.stats['special_skipped']} device node(s) skipped (re-run as root)"
            if self.stats["special_skipped"] else ""
        )
        print(
            f"\nDone: {self.stats['added']} added, {self.stats['overwritten']} overwritten, "
            f"{self.stats['deleted']} deleted, {self.stats['missing_layers']} missing layer(s), "
            f"{self.stats['special']} special file(s){skipped_note}."
        )

    def _apply_layer(self, layer_diff: Path, target: Path):
        for dirpath, dirnames, filenames in os.walk(layer_diff, followlinks=False):
            rel     = Path(dirpath).relative_to(layer_diff)
            tgt_dir = target / rel

            tgt_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(tgt_dir, stat.S_IMODE(Path(dirpath).stat().st_mode))
            except OSError:
                pass
            _copy_xattrs(Path(dirpath), tgt_dir)

            # ── Opaque whiteout: wipe directory contents ──────────────────
            if ".wh..wh..opq" in filenames:
                for child in list(tgt_dir.iterdir()):
                    if child.is_dir() and not child.is_symlink():
                        shutil.rmtree(child)
                    else:
                        child.unlink(missing_ok=True)

            # ── Whiteout dirs ─────────────────────────────────────────────
            clean_dirs = []
            for dname in dirnames:
                if dname.startswith(".wh."):
                    victim = tgt_dir / dname[4:]
                    if victim.is_symlink() or victim.is_file():
                        victim.unlink(missing_ok=True)
                        self.stats["deleted"] += 1
                    elif victim.is_dir():
                        shutil.rmtree(victim)
                        self.stats["deleted"] += 1
                else:
                    clean_dirs.append(dname)
            dirnames[:] = clean_dirs

            # ── Files ─────────────────────────────────────────────────────
            for fname in filenames:
                if fname == ".wh..wh..opq":
                    continue

                src      = Path(dirpath) / fname
                tgt_file = tgt_dir / fname

                if fname.startswith(".wh."):
                    victim = tgt_dir / fname[4:]
                    if victim.is_symlink() or victim.is_file():
                        victim.unlink(missing_ok=True)
                        self.stats["deleted"] += 1
                    elif victim.is_dir():
                        shutil.rmtree(victim)
                        self.stats["deleted"] += 1
                    continue

                existed   = tgt_file.exists() or tgt_file.is_symlink()
                written   = True
                src_lstat = src.lstat()
                src_mode  = src_lstat.st_mode

                if stat.S_ISLNK(src_mode):
                    if existed:
                        _clear(tgt_file)
                    os.symlink(os.readlink(src), tgt_file)
                    _copy_xattrs(src, tgt_file)

                elif stat.S_ISREG(src_mode):
                    try:
                        shutil.copy2(src, tgt_file)
                    except PermissionError:
                        tgt_file.unlink(missing_ok=True)
                        shutil.copy2(src, tgt_file)
                    os.chmod(tgt_file, stat.S_IMODE(src_mode))
                    _copy_xattrs(src, tgt_file)

                elif stat.S_ISFIFO(src_mode):
                    if existed:
                        _clear(tgt_file)
                    os.mkfifo(tgt_file, stat.S_IMODE(src_mode))
                    _copy_xattrs(src, tgt_file)
                    self.stats["special"] += 1

                elif stat.S_ISCHR(src_mode) or stat.S_ISBLK(src_mode):
                    if existed:
                        _clear(tgt_file)
                    try:
                        os.mknod(tgt_file, src_mode, src_lstat.st_rdev)
                        _copy_xattrs(src, tgt_file)
                        self.stats["special"] += 1
                    except PermissionError:
                        written = False
                        self.stats["special_skipped"] += 1
                        if self.verbose:
                            kind = "chr" if stat.S_ISCHR(src_mode) else "blk"
                            print(
                                f"  [!] {kind} device {tgt_file} "
                                f"({os.major(src_lstat.st_rdev)}:{os.minor(src_lstat.st_rdev)})"
                                f": needs root, skipped",
                                file=sys.stderr,
                            )

                elif stat.S_ISSOCK(src_mode):
                    if existed:
                        _clear(tgt_file)
                    try:
                        os.mknod(tgt_file, stat.S_IFSOCK | stat.S_IMODE(src_mode))
                    except OSError:
                        tgt_file.touch(mode=stat.S_IMODE(src_mode))
                    _copy_xattrs(src, tgt_file)
                    self.stats["special"] += 1

                else:
                    written = False
                    if self.verbose:
                        print(
                            f"  [!] Unknown file type {oct(src_mode)} at {tgt_file}, skipped",
                            file=sys.stderr,
                        )

                if written:
                    if existed:
                        self.stats["overwritten"] += 1
                    else:
                        self.stats["added"] += 1


# ──────────────────────────────────────────────────────────────────────────────
# Diff helpers
# ──────────────────────────────────────────────────────────────────────────────

def _build_path_set(docker: DockerRoot, cache_ids: list[Optional[str]]) -> set[str]:
    """Return the set of relative paths present across the given layers.

    Used to distinguish Added (A) from Modified (M) entries in a container's
    upper layer: if the path exists in any lower layer, it's a modification.
    """
    paths: set[str] = set()
    for cid in cache_ids:
        if cid is None:
            continue
        diff = docker.overlay2 / cid / "diff"
        if not diff.exists():
            continue
        for root, dirs, files in os.walk(diff, followlinks=False):
            rel = Path(root).relative_to(diff)
            for name in files + dirs:
                paths.add(str(rel / name))
    return paths


def _collect_diff(diff_dir: Path, image_paths: set[str]) -> list[dict]:
    """Walk a container's upper layer and classify each entry as A/M/D.

    Returns a list of dicts with keys: change, type, path, size_bytes, note.
    """
    changes: list[dict] = []

    for dirpath, dirnames, filenames in os.walk(diff_dir, followlinks=False):
        rel = Path(dirpath).relative_to(diff_dir)

        # Opaque whiteout: this entire directory was replaced in the container
        if ".wh..wh..opq" in filenames:
            p = "/" + str(rel) if str(rel) != "." else "/"
            changes.append({
                "change": "D", "type": "opq", "path": p,
                "size_bytes": 0, "note": "opaque whiteout (directory replaced)",
            })

        # Whiteout directory entries
        clean_dirs = []
        for dname in dirnames:
            if dname.startswith(".wh."):
                victim = "/" + str(rel / dname[4:])
                changes.append({"change": "D", "type": "dir", "path": victim,
                                 "size_bytes": 0, "note": ""})
            else:
                clean_dirs.append(dname)
        dirnames[:] = clean_dirs

        # File entries
        for fname in filenames:
            if fname == ".wh..wh..opq":
                continue

            if fname.startswith(".wh."):
                victim = "/" + str(rel / fname[4:])
                changes.append({"change": "D", "type": "file", "path": victim,
                                 "size_bytes": 0, "note": ""})
                continue

            src      = Path(dirpath) / fname
            rel_file = str(rel / fname)       # e.g. "etc/passwd"
            change   = "M" if rel_file in image_paths else "A"
            try:
                size = src.lstat().st_size
            except OSError:
                size = 0
            if src.is_symlink():
                ftype = "sym"
                note  = os.readlink(src)
            else:
                ftype = "file"
                note  = ""
            changes.append({
                "change": change, "type": ftype, "path": "/" + rel_file,
                "size_bytes": size, "note": note,
            })

    changes.sort(key=lambda x: x["path"])
    return changes


# ──────────────────────────────────────────────────────────────────────────────
# Pretty printers
# ──────────────────────────────────────────────────────────────────────────────

def print_image_list(images: list[dict]):
    if not images:
        print("(no images found)")
        return
    print(f"{'SHORT ID':<14}  {'CREATED':<22}  {'OS/ARCH':<18}  {'LAYERS':<7}  TAGS")
    print("─" * 95)
    for img in images:
        cfg = img["config"]
        ident    = short(img["id"])
        created  = fmt_ts(cfg.get("created", ""))
        os_arch  = f"{cfg.get('os', '?')}/{cfg.get('architecture', '?')}"
        layers   = len(cfg.get("rootfs", {}).get("diff_ids", []))
        tags_str = "  ".join(img.get("tags", [])) or "(untagged)"
        print(f"{ident:<14}  {created:<22}  {os_arch:<18}  {layers:<7}  {tags_str}")


def print_container_list(containers: list[dict]):
    if not containers:
        print("(no containers found)")
        return
    print(f"{'SHORT ID':<14}  {'NAME':<28}  {'IMAGE':<20}  STATE")
    print("─" * 85)
    for c in containers:
        cfg        = c["config"]
        ident      = short(c["id"])
        name       = cfg.get("Name", "").lstrip("/") or "(unnamed)"
        image_name = c.get("image_name") or short(cfg.get("Image", "").removeprefix("sha256:"), 12)
        state      = cfg.get("State", {}).get("Status", "?")
        print(f"{ident:<14}  {name:<28}  {image_name:<20}  {state}")


def print_image_inspect(img: dict, docker: DockerRoot):
    cfg  = img["config"]
    ccfg = cfg.get("config", {})
    tags = img.get("tags") or docker.image_tags().get(img["id"], [])
    print(f"=== Image {short(img['id'])} ===")
    print(f"  Full ID   : sha256:{img['id']}")
    print(f"  Tags      : {', '.join(tags) if tags else '(untagged)'}")
    print(f"  Created   : {fmt_ts(cfg.get('created', ''))}")
    print(f"  OS/Arch   : {cfg.get('os', '?')}/{cfg.get('architecture', '?')}")
    print(f"  Docker ver: {cfg.get('docker_version', '?')}")

    diff_ids = cfg.get("rootfs", {}).get("diff_ids", [])
    print(f"\n  Layers ({len(diff_ids)}):")
    cache_ids = docker.image_cache_ids(img["id"])
    for i, (did, cid) in enumerate(zip(diff_ids, cache_ids)):
        on_disk = "✓" if cid and (docker.overlay2 / cid / "diff").exists() else "✗ missing"
        size_str = ""
        if cid and (docker.overlay2 / cid / "diff").exists():
            size = _dir_size(docker.overlay2 / cid / "diff")
            size_str = f"  ({fmt_size(size)})"
        print(f"    [{i}] {short(did.removeprefix('sha256:'), 20)}  cache={short(cid or '?', 12)}  {on_disk}{size_str}")

    env = ccfg.get("Env", []) or []
    if env:
        print(f"\n  Environment ({len(env)}):")
        for e in env:
            print(f"    {e}")

    cmd = ccfg.get("Cmd") or cfg.get("Cmd")
    ep  = ccfg.get("Entrypoint") or cfg.get("Entrypoint")
    if ep:
        print(f"\n  Entrypoint: {ep}")
    if cmd:
        print(f"  Cmd       : {cmd}")

    exposed = ccfg.get("ExposedPorts", {})
    if exposed:
        print(f"\n  Exposed ports: {', '.join(exposed.keys())}")

    labels = ccfg.get("Labels", {}) or {}
    if labels:
        print(f"\n  Labels ({len(labels)}):")
        for k, v in labels.items():
            print(f"    {k} = {v}")

    history = cfg.get("history", [])
    if history:
        print(f"\n  Build history ({len(history)} steps):")
        for i, h in enumerate(history):
            created_by = h.get("created_by", "")
            if len(created_by) > 100:
                created_by = created_by[:97] + "…"
            empty = "  (empty layer)" if h.get("empty_layer") else ""
            print(f"    [{i}] {created_by}{empty}")


def print_container_inspect(c: dict, docker: DockerRoot):
    cfg  = c["config"]
    ccfg = cfg.get("Config", {})
    st   = cfg.get("State", {})

    print(f"=== Container {short(c['id'])} ===")
    print(f"  Full ID   : {c['id']}")
    print(f"  Name      : {cfg.get('Name', '').lstrip('/')}")
    image_name = c.get("image_name", "")
    image_id   = cfg.get("Image", "")
    if image_name and image_id:
        print(f"  Image     : {image_name}  ({image_id})")
    else:
        print(f"  Image     : {image_name or image_id}")
    print(f"  Created   : {fmt_ts(cfg.get('Created', ''))}")

    print(f"\n  State:")
    print(f"    Status     : {st.get('Status', '?')}")
    print(f"    Running    : {st.get('Running', False)}")
    print(f"    Paused     : {st.get('Paused', False)}")
    print(f"    Restarting : {st.get('Restarting', False)}")
    print(f"    ExitCode   : {st.get('ExitCode', '?')}")
    if st.get("StartedAt"):
        print(f"    Started    : {fmt_ts(st['StartedAt'])}")
    if st.get("FinishedAt") and st["FinishedAt"] != "0001-01-01T00:00:00Z":
        print(f"    Finished   : {fmt_ts(st['FinishedAt'])}")
    if st.get("Error"):
        print(f"    Error      : {st['Error']}")

    env = ccfg.get("Env", []) or []
    if env:
        print(f"\n  Environment ({len(env)}):")
        for e in env:
            print(f"    {e}")

    cmd = ccfg.get("Cmd") or []
    ep  = ccfg.get("Entrypoint") or []
    if ep:
        print(f"\n  Entrypoint: {ep}")
    if cmd:
        print(f"  Cmd       : {cmd}")

    hcfg = cfg.get("HostConfig", {})
    binds = hcfg.get("Binds") or []
    if binds:
        print(f"\n  Volume binds:")
        for b in binds:
            print(f"    {b}")

    mounts = cfg.get("MountPoints", {})
    if mounts:
        print(f"\n  Mount points ({len(mounts)}):")
        for dest, m in mounts.items():
            print(f"    {dest} → source={m.get('Source', '?')}  rw={m.get('RW', '?')}")

    net = cfg.get("NetworkSettings", {})
    if net:
        nets = net.get("Networks", {})
        if nets:
            print(f"\n  Networks:")
            for netname, info in nets.items():
                ip = info.get("IPAddress", "?")
                gw = info.get("Gateway", "?")
                mac = info.get("MacAddress", "?")
                print(f"    {netname}: IP={ip}  GW={gw}  MAC={mac}")

    ports = net.get("Ports", {})
    if ports:
        print(f"\n  Port bindings:")
        for cport, bindings in ports.items():
            if bindings:
                for b in bindings:
                    print(f"    {cport} → {b.get('HostIp', '0.0.0.0')}:{b.get('HostPort', '?')}")
            else:
                print(f"    {cport} (not published)")

    restart = hcfg.get("RestartPolicy", {})
    if restart:
        print(f"\n  Restart policy: {restart.get('Name', '?')}  (MaxRetry={restart.get('MaximumRetryCount', 0)})")

    labels = ccfg.get("Labels", {}) or {}
    if labels:
        print(f"\n  Labels ({len(labels)}):")
        for k, v in labels.items():
            print(f"    {k} = {v}")

    upper_id = docker.container_upper_id(c["id"])
    print(f"\n  Upper layer: {upper_id or '(not found)'}")
    if upper_id:
        diff = docker.overlay2 / upper_id / "diff"
        if diff.exists():
            size = _dir_size(diff)
            changes = _count_files(diff)
            print(f"    diff size : {fmt_size(size)}  ({changes} entries)")

    log_path = docker.container_log_path(c["id"])
    if log_path:
        size = log_path.stat().st_size
        print(f"\n  Log file  : {log_path}  ({fmt_size(size)})")


def print_layer_list(cache_ids: list[Optional[str]], docker: DockerRoot, label: str = "image",
                     roles: Optional[list[str]] = None):
    print(f"Layers for {label} (bottom → top):")
    for i, cid in enumerate(cache_ids):
        role_tag = f"  [{roles[i]}]" if roles else ""
        if cid is None:
            print(f"  [{i}]{role_tag}  (layer missing from filesystem)")
            continue
        diff = docker.overlay2 / cid / "diff"
        on_disk = "✓" if diff.exists() else "✗ missing"
        size_str = ""
        if diff.exists():
            size = _dir_size(diff)
            size_str = f"  {fmt_size(size)}"
        print(f"  [{i}]{role_tag}  {cid:<70}  {on_disk}{size_str}")


def print_diff_list(changes: list[dict], c: dict, image_label: str):
    cid   = short(c["id"])
    name  = c["config"].get("Name", "").lstrip("/") or cid
    added = sum(1 for ch in changes if ch["change"] == "A")
    modf  = sum(1 for ch in changes if ch["change"] == "M")
    deld  = sum(1 for ch in changes if ch["change"] == "D")
    print(f"Container diff: {cid}  name={name}  image={image_label}")
    print(f"── {added} added, {modf} modified, {deld} deleted")
    if not changes:
        print("  (no changes in upper layer)")
        return
    print()
    for ch in changes:
        sym   = ch["change"]
        ftype = ch["type"]
        path  = ch["path"]
        note  = ch.get("note", "")
        if sym == "D":
            extra = f"  ({note})" if note else ""
            print(f"  {sym}  {ftype:<4}  {path}{extra}")
        elif ftype == "sym":
            print(f"  {sym}  {ftype:<4}  {path}  → {note}")
        else:
            size_str = f"  {fmt_size(ch['size_bytes'])}" if ch["size_bytes"] else ""
            print(f"  {sym}  {ftype:<4}  {path}{size_str}")


# ──────────────────────────────────────────────────────────────────────────────
# JSON serialisers
# ──────────────────────────────────────────────────────────────────────────────

def _image_to_dict(img: dict, docker: DockerRoot) -> dict:
    cfg  = img["config"]
    ccfg = cfg.get("config", {})
    tags = img.get("tags") or docker.image_tags().get(img["id"], [])

    diff_ids  = cfg.get("rootfs", {}).get("diff_ids", [])
    cache_ids = docker.image_cache_ids(img["id"])
    layers = []
    for i, (did, cid) in enumerate(zip(diff_ids, cache_ids)):
        on_disk = bool(cid and (docker.overlay2 / cid / "diff").exists())
        size    = _dir_size(docker.overlay2 / cid / "diff") if on_disk and cid else 0
        layers.append({"index": i, "diff_id": did, "cache_id": cid,
                        "on_disk": on_disk, "size_bytes": size})
    return {
        "id": "sha256:" + img["id"],
        "short_id": short(img["id"]),
        "tags": tags,
        "created": cfg.get("created", ""),
        "os": cfg.get("os", ""),
        "architecture": cfg.get("architecture", ""),
        "docker_version": cfg.get("docker_version", ""),
        "layers": layers,
        "env": ccfg.get("Env", []) or [],
        "entrypoint": ccfg.get("Entrypoint") or [],
        "cmd": ccfg.get("Cmd") or [],
        "exposed_ports": list((ccfg.get("ExposedPorts") or {}).keys()),
        "labels": ccfg.get("Labels") or {},
        "history": [
            {"created_by": h.get("created_by", ""), "empty_layer": h.get("empty_layer", False)}
            for h in cfg.get("history", [])
        ],
    }


def _container_to_dict(c: dict, docker: DockerRoot) -> dict:
    cfg  = c["config"]
    ccfg = cfg.get("Config", {})
    st   = cfg.get("State", {})
    hcfg = cfg.get("HostConfig", {})
    net  = cfg.get("NetworkSettings", {})

    upper_id   = docker.container_upper_id(c["id"])
    upper_info = None
    if upper_id:
        diff = docker.overlay2 / upper_id / "diff"
        if diff.exists():
            upper_info = {
                "cache_id": upper_id,
                "size_bytes": _dir_size(diff),
                "file_count": _count_files(diff),
            }

    mounts = [
        {"destination": dest, "source": m.get("Source", ""), "rw": m.get("RW", True)}
        for dest, m in (cfg.get("MountPoints") or {}).items()
    ]
    networks = {
        name: {"ip": info.get("IPAddress", ""), "gateway": info.get("Gateway", ""),
               "mac": info.get("MacAddress", "")}
        for name, info in (net.get("Networks") or {}).items()
    }
    ports = {
        cport: [{"host_ip": b.get("HostIp", ""), "host_port": b.get("HostPort", "")}
                for b in (bindings or [])]
        for cport, bindings in (net.get("Ports") or {}).items()
    }
    restart = hcfg.get("RestartPolicy") or {}

    log_path = docker.container_log_path(c["id"])

    return {
        "id": c["id"],
        "short_id": short(c["id"]),
        "name": cfg.get("Name", "").lstrip("/"),
        "image": c.get("image_name", ""),
        "image_id": cfg.get("Image", ""),
        "created": cfg.get("Created", ""),
        "state": {
            "status": st.get("Status", ""),
            "running": st.get("Running", False),
            "paused": st.get("Paused", False),
            "exit_code": st.get("ExitCode", 0),
            "started_at": st.get("StartedAt", ""),
            "finished_at": st.get("FinishedAt", ""),
            "error": st.get("Error", ""),
        },
        "env": ccfg.get("Env", []) or [],
        "entrypoint": ccfg.get("Entrypoint") or [],
        "cmd": ccfg.get("Cmd") or [],
        "binds": hcfg.get("Binds") or [],
        "mounts": mounts,
        "networks": networks,
        "ports": ports,
        "restart_policy": {
            "name": restart.get("Name", ""),
            "max_retry": restart.get("MaximumRetryCount", 0),
        },
        "labels": ccfg.get("Labels") or {},
        "upper_layer": upper_info,
        "log_file": str(log_path) if log_path else None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────────────────────────────────────

def _dir_size(path: Path) -> int:
    total = 0
    try:
        for root, dirs, files in os.walk(path, followlinks=False):
            for f in files:
                try:
                    total += os.lstat(os.path.join(root, f)).st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _count_files(path: Path) -> int:
    count = 0
    try:
        for _, _, files in os.walk(path, followlinks=False):
            count += len(files)
    except OSError:
        pass
    return count


def _clear(p: Path) -> None:
    """Remove whatever is at *p* — file, symlink, or directory tree."""
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    else:
        p.unlink(missing_ok=True)


def _copy_xattrs(src: Path, dst: Path) -> None:
    """Copy all extended attributes from *src* to *dst* without following symlinks."""
    try:
        names = os.listxattr(src, follow_symlinks=False)
    except (OSError, AttributeError):
        return
    for name in names:
        try:
            val = os.getxattr(src, name, follow_symlinks=False)
            os.setxattr(dst, name, val, follow_symlinks=False)
        except OSError:
            pass


def _file_sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of a file's content, or '' on error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _tree_sha256(path: Path) -> str:
    """Deterministic Merkle-style SHA-256 of a directory tree.

    Walk order is lexicographic. Each entry contributes one line to the outer
    hash: ``f <rel>\0<content-sha256>\n`` for regular files,
    ``l <rel>\0<link-target>\n`` for symlinks, ``d <rel>\n`` for directories.
    """
    outer = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames.sort()
        rel = Path(dirpath).relative_to(path)
        if str(rel) != ".":
            outer.update(f"d {rel}\n".encode())
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel_file = rel / fname
            try:
                if fpath.is_symlink():
                    target = os.readlink(fpath)
                    outer.update(f"l {rel_file}\0{target}\n".encode())
                else:
                    inner = hashlib.sha256()
                    with open(fpath, "rb") as fh:
                        for chunk in iter(lambda: fh.read(65536), b""):
                            inner.update(chunk)
                    outer.update(f"f {rel_file}\0{inner.hexdigest()}\n".encode())
            except OSError:
                pass
    return outer.hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# Forensic report builder
# ──────────────────────────────────────────────────────────────────────────────

_TOOL_VERSION = "0.1.0"


def _tool_version() -> str:
    try:
        from importlib.metadata import version
        return version("docker-forensics")
    except Exception:
        return _TOOL_VERSION


class ReportBuilder:
    """Build a self-contained Markdown forensic report from a DockerRoot."""

    def __init__(self, docker: DockerRoot, hash_layers: bool = False,
                 progress_cb=None):
        self.docker = docker
        self.hash_layers = hash_layers
        self._progress = progress_cb or (lambda _msg: None)

    def build(self) -> str:
        buf = io.StringIO()
        w = buf.write

        now_utc = datetime.now(timezone.utc)
        ts_str   = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        report_id = str(uuid.uuid4())
        ver = _tool_version()

        # ── 1. Header ─────────────────────────────────────────────────────────
        w("# Docker Forensic Report\n\n")
        w(f"| Field | Value |\n|---|---|\n")
        w(f"| Tool | docker-forensics {ver} |\n")
        w(f"| Report ID | `{report_id}` |\n")
        w(f"| Generated | `{ts_str}` |\n")
        w(f"| Clock note | Local system clock — not NTP-verified (airgapped) |\n")
        w(f"| Evidence root | `{self.docker.root.resolve()}` |\n\n")

        # ── 2. Environment ────────────────────────────────────────────────────
        w("## Examiner Environment\n\n")
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "(unknown)"
        try:
            username = getpass.getuser()
        except Exception:
            username = "(unknown)"
        w(f"| Field | Value |\n|---|---|\n")
        w(f"| Hostname | `{hostname}` |\n")
        w(f"| User | `{username}` (uid={os.getuid()}, euid={os.geteuid()}) |\n")
        w(f"| Python | `{sys.version.split()[0]}` |\n")
        w(f"| Platform | `{platform.platform()}` |\n")
        w(f"| CWD | `{Path.cwd()}` |\n")
        w(f"| Invocation | `{' '.join(sys.argv)}` |\n\n")

        # ── 3. Evidence source ────────────────────────────────────────────────
        self._progress("Hashing evidence source files…")
        w("## Evidence Source\n\n")
        w(f"Docker root: `{self.docker.root.resolve()}`\n\n")
        w(f"| Path | Present | Entries/Size | SHA-256 (files only) | mtime |\n")
        w(f"|---|---|---|---|---|\n")
        checks = [
            self.docker.overlay2,
            self.docker.image_db / "imagedb",
            self.docker.image_db / "layerdb",
            self.docker.image_db / "repositories.json",
            self.docker.containers,
        ]
        for cp in checks:
            rel = cp.relative_to(self.docker.root) if cp.is_relative_to(self.docker.root) else cp
            exists = cp.exists()
            if not exists:
                w(f"| `{rel}` | NO | — | — | — |\n")
                continue
            if cp.is_file():
                st = cp.stat()
                sha = _file_sha256(cp)
                mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ")
                w(f"| `{rel}` | yes | {fmt_size(st.st_size)} | `{sha}` | `{mtime}` |\n")
            else:
                try:
                    n = sum(1 for _ in cp.iterdir())
                except OSError:
                    n = "?"
                w(f"| `{rel}` | yes | {n} entries | — | — |\n")
        w("\n")

        # ── 4. Image inventory ────────────────────────────────────────────────
        self._progress("Collecting images…")
        images = self.docker.images()
        w(f"## Images ({len(images)})\n\n")
        if images:
            w("| Short ID | Tags | Created | OS/Arch | Docker Ver | Layers | Size | Config SHA-256 |\n")
            w("|---|---|---|---|---|---|---|---|\n")
            for img in images:
                cfg   = img["config"]
                sid   = short(img["id"])
                tags  = ", ".join(img.get("tags", [])) or "(untagged)"
                ctime = cfg.get("created", "")
                osarch = f"{cfg.get('os','?')}/{cfg.get('architecture','?')}"
                dver  = cfg.get("docker_version", "?")
                nlyr  = len(cfg.get("rootfs", {}).get("diff_ids", []))
                # total size of all layers
                try:
                    cids = self.docker.image_cache_ids(img["id"])
                    total_size = sum(
                        _dir_size(self.docker.overlay2 / cid / "diff")
                        for cid in cids if cid and (self.docker.overlay2 / cid / "diff").exists()
                    )
                except Exception:
                    total_size = 0
                # config file hash
                cfg_path = (self.docker.image_db / "imagedb" / "content" / "sha256" / img["id"])
                cfg_sha  = _file_sha256(cfg_path) if cfg_path.exists() else ""
                w(f"| `{sid}` | {tags} | `{ctime}` | {osarch} | {dver} | {nlyr}"
                  f" | {fmt_size(total_size)} | `{cfg_sha[:16]}…` |\n")
            w("\n")

            for img in images:
                self._progress(f"Detailing image {short(img['id'])}…")
                self._write_image_detail(buf, img)
        else:
            w("_(no images found)_\n\n")

        # ── 5. Container inventory ────────────────────────────────────────────
        self._progress("Collecting containers…")
        containers = self.docker.containers_list()
        w(f"## Containers ({len(containers)})\n\n")
        if containers:
            w("| Short ID | Name | Image | State | Created | Started | Finished |\n")
            w("|---|---|---|---|---|---|---|\n")
            for c in containers:
                cfg  = c["config"]
                st   = cfg.get("State", {})
                sid  = short(c["id"])
                name = cfg.get("Name", "").lstrip("/") or "(unnamed)"
                img  = c.get("image_name") or short(cfg.get("Image", "").removeprefix("sha256:"), 12)
                state = st.get("Status", "?")
                ctime = cfg.get("Created", "")
                start = st.get("StartedAt", "")
                fin   = st.get("FinishedAt", "")
                if fin == "0001-01-01T00:00:00Z":
                    fin = ""
                w(f"| `{sid}` | {name} | {img} | {state} | `{ctime}` | `{start}` | `{fin}` |\n")
            w("\n")

            for c in containers:
                self._progress(f"Detailing container {short(c['id'])}…")
                self._write_container_detail(buf, c)
        else:
            w("_(no containers found)_\n\n")

        # ── 6. Warnings ───────────────────────────────────────────────────────
        all_warnings = self.docker.warnings[:]
        w("## Warnings\n\n")
        if all_warnings:
            for warn in all_warnings:
                w(f"- {warn}\n")
        else:
            w("_(none)_\n")
        w("\n")

        body = buf.getvalue()
        digest = hashlib.sha256(body.encode()).hexdigest()
        body += "---\n\n"
        body += f"**Report body SHA-256:** `{digest}`  \n"
        body += "_(Strip this line and re-hash to verify integrity.)_\n"
        return body

    def _write_image_detail(self, buf: io.StringIO, img: dict):
        w = buf.write
        cfg  = img["config"]
        sid  = short(img["id"])
        tags = ", ".join(img.get("tags", [])) or "(untagged)"
        w(f"### Image `{sid}` — {tags}\n\n")
        w(f"- Full ID: `sha256:{img['id']}`\n")
        w(f"- Created: `{cfg.get('created', '')}`\n")
        history = cfg.get("history", [])
        if history:
            w(f"\n**Build history ({len(history)} steps):**\n\n")
            for i, h in enumerate(history):
                cb = h.get("created_by", "")[:100]
                empty = " _(empty layer)_" if h.get("empty_layer") else ""
                w(f"  {i}. `{cb}`{empty}\n")
        w("\n**Layers:**\n\n")
        w("| # | Diff ID (short) | Cache ID | On disk | Size |")
        if self.hash_layers:
            w(" Tree SHA-256 |")
        w("\n|---|---|---|---|---|")
        if self.hash_layers:
            w("---|")
        w("\n")
        try:
            diff_ids  = cfg.get("rootfs", {}).get("diff_ids", [])
            cache_ids = self.docker.image_cache_ids(img["id"])
            for i, (did, cid) in enumerate(zip(diff_ids, cache_ids)):
                diff_dir = self.docker.overlay2 / cid / "diff" if cid else None
                on_disk  = bool(diff_dir and diff_dir.exists())
                size     = fmt_size(_dir_size(diff_dir)) if on_disk and diff_dir else "—"
                did_s    = short(did.removeprefix("sha256:"), 16)
                cid_s    = short(cid or "?", 16)
                w(f"| {i} | `{did_s}` | `{cid_s}` | {'yes' if on_disk else 'NO'} | {size} |")
                if self.hash_layers:
                    tree_h = _tree_sha256(diff_dir) if on_disk and diff_dir else "—"
                    w(f" `{tree_h[:16]}…` |")
                w("\n")
        except Exception as exc:
            msg = f"[!] layer detail failed for {sid}: {exc}"
            self.docker.warnings.append(msg)
            w(f"\n_{msg}_\n")
        w("\n")

    def _write_container_detail(self, buf: io.StringIO, c: dict):
        w = buf.write
        cfg  = c["config"]
        st   = cfg.get("State", {})
        hcfg = cfg.get("HostConfig") or {}
        sid  = short(c["id"])
        name = cfg.get("Name", "").lstrip("/") or "(unnamed)"
        w(f"### Container `{sid}` — {name}\n\n")
        w(f"- Full ID: `{c['id']}`\n")
        w(f"- Image: {c.get('image_name') or cfg.get('Image', '')}\n")
        w(f"- State: {st.get('Status', '?')} (exit code {st.get('ExitCode', '?')})\n")

        # config file hash
        cfg_path = self.docker.containers / c["id"] / "config.v2.json"
        cfg_sha  = _file_sha256(cfg_path) if cfg_path.exists() else ""
        if cfg_sha:
            w(f"- Config SHA-256: `{cfg_sha}`\n")

        # upper layer
        upper_id = self.docker.container_upper_id(c["id"])
        if upper_id:
            diff = self.docker.overlay2 / upper_id / "diff"
            on_disk = diff.exists()
            w(f"\n**Writable upper layer:** `{upper_id}`")
            if on_disk:
                sz = fmt_size(_dir_size(diff))
                fc = _count_files(diff)
                w(f"  ({sz}, {fc} files)")
                if self.hash_layers:
                    w(f"  tree SHA-256: `{_tree_sha256(diff)}`")
            else:
                w("  _(not on disk)_")
            w("\n")

            # diff summary
            if on_disk:
                try:
                    image_id = cfg.get("Image", "").removeprefix("sha256:")
                    img_cache = self.docker.image_cache_ids(image_id) if image_id else []
                    init_id   = self.docker.container_init_id(c["id"])
                    lower_ids = img_cache + ([init_id] if init_id else [])
                    img_paths = _build_path_set(self.docker, lower_ids)
                    changes   = _collect_diff(diff, img_paths)
                    added   = sum(1 for ch in changes if ch["change"] == "A")
                    modf    = sum(1 for ch in changes if ch["change"] == "M")
                    deld    = sum(1 for ch in changes if ch["change"] == "D")
                    w(f"\n**Filesystem diff:** {added} added, {modf} modified, {deld} deleted\n\n")
                    if changes:
                        w("| Change | Type | Path | Size | Note |\n|---|---|---|---|---|\n")
                        for ch in changes[:200]:
                            size_s = fmt_size(ch["size_bytes"]) if ch.get("size_bytes") else "—"
                            note   = ch.get("note", "")
                            w(f"| {ch['change']} | {ch['type']} | `{ch['path']}` | {size_s} | {note} |\n")
                        if len(changes) > 200:
                            w(f"\n_…{len(changes) - 200} more entries omitted_\n")
                        w("\n")
                except Exception as exc:
                    msg = f"[!] diff failed for {sid}: {exc}"
                    self.docker.warnings.append(msg)
                    w(f"\n_{msg}_\n")

        # log file
        log_path = self.docker.container_log_path(c["id"])
        if log_path:
            log_sha  = _file_sha256(log_path)
            log_size = log_path.stat().st_size
            w(f"\n**Log file:** `{log_path}`  \n")
            w(f"Size: {fmt_size(log_size)}  SHA-256: `{log_sha}`  \n")
            # count lines / errors
            lines_ok = 0
            errors   = 0
            try:
                with open(log_path, "r", errors="replace") as fh:
                    for raw in fh:
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            json.loads(raw)
                            lines_ok += 1
                        except json.JSONDecodeError:
                            errors += 1
            except OSError:
                pass
            w(f"Lines: {lines_ok}")
            if errors:
                msg = f"log parse errors in {sid}: {errors} non-JSON line(s)"
                self.docker.warnings.append(msg)
                w(f"  _(parse errors: {errors})_")
            w("\n\n")
        else:
            driver = hcfg.get("LogConfig", {}).get("Type", "")
            if driver and driver != "json-file":
                w(f"\n**Log:** no file found (log driver: `{driver}`)\n\n")
            else:
                w(f"\n**Log:** no file found\n\n")


# ──────────────────────────────────────────────────────────────────────────────
# CLI commands
# ──────────────────────────────────────────────────────────────────────────────

def cmd_list(args, docker: DockerRoot):
    images     = docker.images()
    containers = docker.containers_list()

    if args.json:
        imgs = [
            {
                "id": "sha256:" + img["id"],
                "short_id": short(img["id"]),
                "tags": img.get("tags", []),
                "created": img["config"].get("created", ""),
                "os": img["config"].get("os", ""),
                "architecture": img["config"].get("architecture", ""),
                "layer_count": len(img["config"].get("rootfs", {}).get("diff_ids", [])),
            }
            for img in images
        ]
        ctrs = [
            {
                "id": c["id"],
                "short_id": short(c["id"]),
                "name": c["config"].get("Name", "").lstrip("/"),
                "image": c.get("image_name", ""),
                "state": c["config"].get("State", {}).get("Status", ""),
            }
            for c in containers
        ]
        print(json.dumps({"docker_root": str(docker.root), "images": imgs, "containers": ctrs},
                         indent=2))
        return

    print(f"Docker root: {docker.root}\n")
    print(f"── Images ({len(images)}) ───────────────────────────────────────────────")
    print_image_list(images)
    print(f"\n── Containers ({len(containers)}) ──────────────────────────────────────────")
    print_container_list(containers)


def cmd_inspect(args, docker: DockerRoot):
    kind   = args.kind
    prefix = args.id

    if kind == "image":
        img = docker.resolve_image(prefix)
        if args.json:
            print(json.dumps(_image_to_dict(img, docker), indent=2))
        else:
            print_image_inspect(img, docker)

    elif kind == "container":
        c = docker.resolve_container(prefix)
        if args.json:
            print(json.dumps(_container_to_dict(c, docker), indent=2))
        else:
            print_container_inspect(c, docker)


def cmd_layers(args, docker: DockerRoot):
    kind   = args.kind
    prefix = args.id

    if kind == "image":
        img       = docker.resolve_image(prefix)
        cache_ids = docker.image_cache_ids(img["id"])
        roles     = ["image"] * len(cache_ids)
        label     = f"image {short(img['id'])}"

    elif kind == "container":
        c        = docker.resolve_container(prefix)
        image_id = c["config"].get("Image", "").removeprefix("sha256:")
        if not image_id:
            print("Cannot determine image ID from container config.", file=sys.stderr)
            sys.exit(1)
        cache_ids = docker.image_cache_ids(image_id)
        roles     = ["image"] * len(cache_ids)
        init_id   = docker.container_init_id(c["id"])
        upper     = docker.container_upper_id(c["id"])
        if init_id:
            cache_ids.append(init_id)
            roles.append("init")
        if upper:
            cache_ids.append(upper)
            roles.append("upper")
        label = f"container {short(c['id'])}"

    if args.json:
        layers_out = []
        for i, (cid, role) in enumerate(zip(cache_ids, roles)):
            on_disk = bool(cid and (docker.overlay2 / cid / "diff").exists())
            size    = _dir_size(docker.overlay2 / cid / "diff") if on_disk and cid else 0
            layers_out.append({"index": i, "cache_id": cid, "on_disk": on_disk,
                                "size_bytes": size, "role": role})
        print(json.dumps({"label": label, "layers": layers_out}, indent=2))
    else:
        print_layer_list(cache_ids, docker, label=label, roles=roles)


def cmd_diff(args, docker: DockerRoot):
    prefix = args.id

    c        = docker.resolve_container(prefix)
    image_id = c["config"].get("Image", "").removeprefix("sha256:")
    if not image_id:
        print("Cannot determine image ID from container config.", file=sys.stderr)
        sys.exit(1)

    upper_id = docker.container_upper_id(c["id"])
    if not upper_id:
        print(f"Cannot find upper layer for container {short(c['id'])}", file=sys.stderr)
        sys.exit(1)

    diff_dir = docker.overlay2 / upper_id / "diff"
    if not diff_dir.exists():
        print(f"Upper layer diff/ not found: {diff_dir}", file=sys.stderr)
        sys.exit(1)

    # Build path set from image + init layers to distinguish A vs M
    image_cache_ids = docker.image_cache_ids(image_id)
    init_id         = docker.container_init_id(c["id"])
    lower_ids       = image_cache_ids + ([init_id] if init_id else [])
    image_paths     = _build_path_set(docker, lower_ids)

    changes = _collect_diff(diff_dir, image_paths)

    if args.json:
        added = sum(1 for ch in changes if ch["change"] == "A")
        modf  = sum(1 for ch in changes if ch["change"] == "M")
        deld  = sum(1 for ch in changes if ch["change"] == "D")
        print(json.dumps({
            "container_id": c["id"],
            "container_name": c["config"].get("Name", "").lstrip("/"),
            "image": c.get("image_name", ""),
            "image_id": "sha256:" + image_id,
            "upper_layer": upper_id,
            "summary": {"added": added, "modified": modf, "deleted": deld},
            "changes": changes,
        }, indent=2))
    else:
        print_diff_list(changes, c, c.get("image_name") or short(image_id))


def cmd_log(args, docker: DockerRoot):
    prefix = args.id

    c        = docker.resolve_container(prefix)
    log_path = docker.container_log_path(c["id"])

    if not log_path:
        driver = (c["config"].get("HostConfig") or {}).get("LogConfig", {}).get("Type", "")
        driver_note = f"  (log driver: {driver})" if driver and driver != "json-file" else ""
        print(f"No log file found for container {short(c['id'])}{driver_note}", file=sys.stderr)
        sys.exit(1)

    stdout_only = args.stdout
    stderr_only = args.stderr
    as_json     = args.json

    entries: list[dict] = []
    errors = 0
    with open(log_path, "r", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                errors += 1
                continue
            stream = entry.get("stream", "")
            if stdout_only and stream != "stdout":
                continue
            if stderr_only and stream != "stderr":
                continue
            entries.append(entry)

    if as_json:
        print(json.dumps({
            "container_id": c["id"],
            "container_name": c["config"].get("Name", "").lstrip("/"),
            "log_file": str(log_path),
            "line_count": len(entries),
            "parse_errors": errors,
            "entries": entries,
        }, indent=2))
        return

    cid  = short(c["id"])
    name = c["config"].get("Name", "").lstrip("/") or cid
    print(f"Log: {name} ({cid})  ←  {log_path}")
    if errors:
        print(f"  [{errors} unparseable line(s) skipped]", file=sys.stderr)
    print()
    for entry in entries:
        ts     = entry.get("time", "")[:19].replace("T", " ")
        stream = entry.get("stream", "?")
        text   = entry.get("log", "").rstrip("\n")
        marker = "E" if stream == "stderr" else " "
        print(f"  {ts}  {marker}  {text}")


def cmd_extract(args, docker: DockerRoot):
    kind      = args.kind
    prefix    = args.id
    output    = Path(args.output)
    verbose   = args.verbose

    if output.exists():
        if not output.is_dir():
            print(f"Error: output path '{output}' exists and is not a directory.", file=sys.stderr)
            sys.exit(1)
        if any(output.iterdir()):
            print(f"Error: output directory '{output}' exists and is not empty.", file=sys.stderr)
            print("       Remove it first or choose a different path.", file=sys.stderr)
            sys.exit(1)

    merger = OverlayMerger(docker, verbose=verbose)

    if kind == "image":
        img       = docker.resolve_image(prefix)
        cache_ids = docker.image_cache_ids(img["id"])
        print(f"Extracting image {short(img['id'])}  ({len(cache_ids)} layers) → {output}")
        merger.merge(cache_ids, output)

    elif kind == "container":
        c        = docker.resolve_container(prefix)
        image_id = c["config"].get("Image", "").removeprefix("sha256:")
        if not image_id:
            print("Cannot determine image ID from container config.", file=sys.stderr)
            sys.exit(1)
        cache_ids = docker.image_cache_ids(image_id)
        init_id   = docker.container_init_id(c["id"])
        upper     = docker.container_upper_id(c["id"])
        if init_id:
            cache_ids = cache_ids + [init_id]
        if upper:
            cache_ids = cache_ids + [upper]
        print(
            f"Extracting container {short(c['id'])}  "
            f"({len(cache_ids)} layers, "
            f"init={'yes' if init_id else 'not found'}, "
            f"upper={'yes' if upper else 'not found'}) → {output}"
        )
        merger.merge(cache_ids, output)


def cmd_report(args, docker: DockerRoot):
    output_path = Path(args.output) if args.output else None

    def progress(msg: str):
        if not output_path or args.output == "-":
            return
        print(f"  {msg}", file=sys.stderr)

    builder = ReportBuilder(docker, hash_layers=args.hash_layers, progress_cb=progress)
    report  = builder.build()

    if output_path and str(output_path) != "-":
        output_path.write_text(report, encoding="utf-8")
        print(f"Report written to: {output_path}", file=sys.stderr)
    else:
        sys.stdout.write(report)


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("docker_root", metavar="<docker-root>",
                   help="Path to the Docker data directory (e.g. /mnt/evidence/var/lib/docker)")
    p.add_argument("--tui", action="store_true",
                   help="Launch interactive TUI (no subcommand required)")

    sub = p.add_subparsers(dest="command", required=False)

    # list
    lst = sub.add_parser("list", help="List all images and containers")
    lst.add_argument("--json", action="store_true", help="Output as JSON")

    # inspect
    ins = sub.add_parser("inspect", help="Show metadata for an image or container")
    ins.add_argument("kind", choices=["image", "container"])
    ins.add_argument("id", metavar="<id-prefix>")
    ins.add_argument("--json", action="store_true", help="Output as JSON")

    # layers
    lyr = sub.add_parser("layers", help="Show overlay2 layer chain for an image or container")
    lyr.add_argument("kind", choices=["image", "container"])
    lyr.add_argument("id", metavar="<id-prefix>")
    lyr.add_argument("--json", action="store_true", help="Output as JSON")

    # diff
    dif = sub.add_parser("diff",
                         help="Show filesystem changes in a container's upper layer (A/M/D)")
    dif.add_argument("id", metavar="<id-prefix>",
                     help="Container ID prefix (images have no writable upper layer)")
    dif.add_argument("--json", action="store_true", help="Output as JSON")

    # log
    log = sub.add_parser("log", help="Print a container's captured stdout/stderr log")
    log.add_argument("id", metavar="<id-prefix>")
    log.add_argument("--stdout", action="store_true", help="Show only stdout lines")
    log.add_argument("--stderr", action="store_true", help="Show only stderr lines")
    log.add_argument("--json", action="store_true", help="Output as JSON")

    # extract
    ext = sub.add_parser("extract",
                         help="Reassemble the merged filesystem into an output directory")
    ext.add_argument("kind", choices=["image", "container"])
    ext.add_argument("id", metavar="<id-prefix>")
    ext.add_argument("output", metavar="<output-dir>")
    ext.add_argument("-v", "--verbose", action="store_true",
                     help="Print each layer as it is applied")

    # report
    rep = sub.add_parser("report",
                         help="Generate a self-contained forensic Markdown report")
    rep.add_argument("-o", "--output", metavar="PATH", default=None,
                     help="Write report to PATH instead of stdout (use '-' for stdout)")
    rep.add_argument("--hash-layers", action="store_true",
                     help="Hash every overlay2 diff tree (slow on large evidence)")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()
    docker = DockerRoot(Path(args.docker_root))

    if not docker.root.exists():
        print(f"Error: path does not exist: {docker.root}", file=sys.stderr)
        sys.exit(1)

    if args.tui:
        from docker_tui import run_tui
        run_tui(docker)
        return

    if not args.command:
        parser.print_help()
        sys.exit(1)

    dispatch = {
        "list"   : cmd_list,
        "inspect": cmd_inspect,
        "layers" : cmd_layers,
        "diff"   : cmd_diff,
        "log"    : cmd_log,
        "extract": cmd_extract,
        "report" : cmd_report,
    }
    try:
        dispatch[args.command](args, docker)
    except KeyboardInterrupt:
        print("\n[aborted]", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
