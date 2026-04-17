# docker-examiner

Offline forensic analysis of Docker overlay2 filesystems. A single-file, zero-dependency Python tool for inspecting Docker data directories extracted from forensic images — no running Docker daemon required.

## Features

- List all images and containers found in a Docker data directory
- Inspect image and container configuration (creation time, entrypoint, env, labels, …)
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
docker_forensics.py <docker-root> diff    container <id-prefix> [--json]
docker_forensics.py <docker-root> log     <id-prefix> [--json] [--stdout] [--stderr]
docker_forensics.py <docker-root> extract (image|container) <id-prefix> <output-dir> [-v]
docker_forensics.py <docker-root> report  [-o <path>] [--hash-layers]
```

ID prefixes work like Docker's own short IDs — you only need enough characters to be unambiguous.

### Examples

```bash
# List all images and containers
python docker_forensics.py /mnt/evidence/var/lib/docker list

# Inspect a container by short ID
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

The report includes:

1. **Header** — tool version, UUID, generation timestamp (with explicit airgapped/non-NTP disclosure)
2. **Examiner environment** — hostname, uid, Python version, invocation command
3. **Evidence source** — presence, entry count, SHA-256 and mtime for key paths under the Docker root
4. **Image inventory** — table + per-image layer detail (diff ID, cache ID, on-disk status, size, optional Merkle hash)
5. **Container inventory** — table + per-container detail (config SHA-256, upper-layer diff summary, log file SHA-256 and line count)
6. **Warnings** — any permission errors, missing layers, or JSON parse errors encountered
7. **Integrity footer** — SHA-256 of the full report body; strip the footer line and re-hash with `sha256sum` to verify

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
| Overview | `r` | Prompt for output path and generate forensic report |
| Overview | `q` / `Esc` | Quit |
| Layer Stack | `↑`/`↓` | Select a layer |
| Layer Stack | `Enter` | View layer detail |
| Layer Stack | `a` | Open action menu |
| Layer Stack | `d` | Open diff viewer (containers only) |
| Layer Stack | `l` | Open log viewer (containers only) |
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
