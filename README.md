# docker-examiner

Offline forensic analysis of Docker overlay2 filesystems. A single-file, zero-dependency Python tool for inspecting Docker data directories extracted from forensic images — no running Docker daemon required.

## Features

- List all images and containers found in a Docker data directory
- Inspect image and container configuration (creation time, entrypoint, env, labels, …)
- Show pull origin — the registry and repository an image was pulled from
- Enumerate overlay2 layers for any image or container
- Show the diff (writes/deletes) of a container's writable layer
- Read container stdout/stderr logs
- Extract and reassemble a complete merged filesystem from any image or container, correctly applying overlay2 whiteouts
- Interactive TUI with a size-proportional layer stack visualization

## Requirements

- Python 3.11+
- Linux (overlay2 paths are Linux-specific)
- No third-party dependencies — stdlib only

## Installation

```bash
# Run directly
python docker_forensics.py <docker-root> ...

# Or install as a CLI tool
pip install .
docker-forensics <docker-root> ...
```

## Usage

`<docker-root>` is the path to the Docker data directory on your analysis machine, e.g. `/mnt/evidence/var/lib/docker` or `/cases/001/docker`. The tool also accepts a raw mount root and auto-detects the `var/lib/docker` subdirectory.

```
docker_forensics.py <docker-root> list [--json]
docker_forensics.py <docker-root> inspect (image|container) <id-prefix> [--json]
docker_forensics.py <docker-root> layers  (image|container) <id-prefix> [--json]
docker_forensics.py <docker-root> diff    container <id-prefix> [--filter {A,M,D}] [--json]
docker_forensics.py <docker-root> log     <id-prefix> [--json] [--stdout] [--stderr]
docker_forensics.py <docker-root> extract (image|container) <id-prefix> <output-dir> [-v]
docker_forensics.py <docker-root> report  [-o <path>] [--hash-layers]
```

ID prefixes work like Docker's own short IDs — you only need enough characters to be unambiguous.

### Examples

```bash
# List all images and containers
python docker_forensics.py /mnt/evidence/var/lib/docker list

# Inspect an image — shows pull origin (registry/repo), layers, env, history
python docker_forensics.py /mnt/evidence/var/lib/docker inspect image sha256abc

# Inspect a container by short ID — shows pull origin of its image
python docker_forensics.py /mnt/evidence/var/lib/docker inspect container a3f1

# Show what a container wrote (upper layer diff)
python docker_forensics.py /mnt/evidence/var/lib/docker diff container a3f1

# Read container logs
python docker_forensics.py /mnt/evidence/var/lib/docker log a3f1 --stdout

# Extract full merged filesystem of an image
python docker_forensics.py /mnt/evidence/var/lib/docker extract image nginx:latest ./output
```

## Forensic report

Generate a single self-contained Markdown report covering all images and containers in the evidence root:

```bash
python docker_forensics.py /mnt/evidence/var/lib/docker report -o report.md
```

| Flag | Description |
|------|-------------|
| `-o PATH` / `--output PATH` | Write to file instead of stdout. Use `-` for explicit stdout. |
| `--hash-layers` | Compute a Merkle SHA-256 of every overlay2 `diff/` tree (slow; can read multi-GB). Off by default. |

The TUI `r` key prompts for both the output path and whether to hash layers (`y/N`).

The report includes:

1. **Header** — tool version, UUID, generation timestamp (with explicit airgapped/non-NTP disclosure)
2. **Examiner environment** — hostname, uid, Python version, invocation command
3. **Evidence source** — presence, entry count, SHA-256 and mtime for key paths (`overlay2`, `imagedb`, `layerdb`, `distribution`, `repositories.json`, `containers`, `volumes`, `network`, `plugins`)
4. **Summary** — image and container counts; callout tables for non-zero exits, OOM kills, privileged containers, and images with missing layers
5. **Image inventory** — summary table (with pull origin) + per-image detail: full diff IDs and cache IDs, OS/arch/variant, Docker version, pull origin, entrypoint/cmd, exposed ports, env vars, labels, build history, layer table (full sha256 diff ID, cache ID, on-disk status, size, optional full Merkle hash)
6. **Container inventory** — summary table (with exit code, OOM, privileged columns) + per-container detail: identity (full ID, image, pull origin, created, config SHA-256), full state (running/paused/restarting/OOMKilled/dead/pid/exit code/error/started/finished), runtime config (hostname, domainname, user, workingdir, stopsignal, entrypoint/cmd), security (privileged, readonly rootfs, cap_add/drop, security opts), isolation/namespaces (network/pid/ipc/uts modes), resource limits (memory, swap, CPU, SHM, ulimits, devices), DNS/hosts config, environment variables, mounts table, networks table (IP/gateway/MAC/IPv6), ports table, restart policy, log driver, labels, overlay2 layer IDs (upper + init), full filesystem diff (A/M/D — no truncation), complete log content
7. **Warnings** — any permission errors, missing layers, or JSON parse errors encountered
8. **Integrity footer** — SHA-256 of the full report body; strip the footer line and re-hash with `sha256sum` to verify

## Interactive TUI

Launch the TUI with `--tui` instead of a subcommand:

```bash
python docker_forensics.py /mnt/evidence/var/lib/docker --tui
```

### Navigation

| Screen | Key | Action |
|--------|-----|--------|
| Overview | `↑`/`↓` | Move cursor |
| Overview | `Tab` | Switch between Images and Containers pane |
| Overview | `Enter` | Open layer stack for selected image/container |
| Overview | `i` | Open container config view (containers pane only) |
| Overview | `r` | Prompt for output path and generate forensic report |
| Overview | `q` / `Esc` | Quit |
| Layer Stack | `↑`/`↓` | Select a layer |
| Layer Stack | `Enter` | View layer detail |
| Layer Stack | `a` | Open action menu |
| Layer Stack | `d` | Open diff viewer (containers only) |
| Layer Stack | `l` | Open log viewer (containers only) |
| Layer Stack | `i` | Open container config view (containers only) |
| Layer Stack | `b` | Back to overview |
| Layer Detail | `↑`/`↓` / `PgUp`/`PgDn` | Scroll |
| Layer Detail | `a` | Open action menu |
| Layer Detail | `b` | Back to layer stack |
| Action menu | `↑`/`↓` + `Enter` | Choose action |
| Action menu | `Esc` | Cancel |
| Diff Viewer | `a` / `m` / `d` | Filter by Added / Modified / Deleted |
| Diff Viewer | `c` | Clear filter (show all) |
| Diff Viewer | `b` | Back to layer stack |
| Log Viewer | `s` / `e` | Show only stdout / stderr |
| Log Viewer | `c` | Clear filter (show all) |
| Log Viewer | `b` | Back to layer stack |
| Container Config | `↑`/`↓` / `PgUp`/`PgDn` | Scroll |
| Container Config | `b` | Back to previous screen |
| Container Config | `q` / `Esc` | Quit |

### Layer stack visualization

Each layer is rendered as a box whose **height is proportional to its on-disk size**, so large layers dominate the display and tiny layers occupy a single row. Layers are ordered top-to-bottom: writable upper → init → image layers → base.

Color coding: green = writable upper layer, yellow = init layer, cyan = selected layer, red = layer missing from disk.

### Actions per layer

- **Inspect metadata** — show cache ID, diff ID, size, path, top-level directory entries
- **Export merged FS up to this layer** — reassemble the overlay2 stack from the base up to and including the selected layer into an output directory (runs in the background with a live progress overlay)
- **Export this layer's diff** — copy just that layer's `diff/` directory

## Output directory

The `extract` command merges all overlay2 layers bottom-to-top into `<output-dir>`, honouring whiteout files (`.wh.<name>` for deletions, `.wh..wh..opq` for opaque directories). Running as root is required to preserve device nodes; otherwise they are skipped with a warning.

## License

MIT
