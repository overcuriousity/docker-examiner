# docker-examiner

Offline forensic analysis of Docker overlay2 filesystems. A single-file, zero-dependency Python tool for inspecting Docker data directories extracted from forensic images — no running Docker daemon required.

## Features

- List all images and containers found in a Docker data directory
- Inspect image and container configuration (creation time, entrypoint, env, labels, …)
- Enumerate overlay2 layers for any image or container
- Show the diff (writes/deletes) of a container's writable layer
- Read container stdout/stderr logs
- Extract and reassemble a complete merged filesystem from any image or container, correctly applying overlay2 whiteouts

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

## Output directory

The `extract` command merges all overlay2 layers bottom-to-top into `<output-dir>`, honouring whiteout files (`.wh.<name>` for deletions, `.wh..wh..opq` for opaque directories). Running as root is required to preserve device nodes; otherwise they are skipped with a warning.

## License

MIT
