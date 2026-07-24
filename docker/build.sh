#!/usr/bin/env bash
# Build all extraction tool Docker images
# Usage: bash docker/build.sh
#
# Each image runs ONE security tool in isolation:
#   --network=none --read-only --cap-drop=ALL --no-new-privileges
#   --cpus=0.5 --memory=256m --pids-limit=50

set -e
cd "$(dirname "$0")"

echo "=== Building Attijari extraction containers ==="

IMAGES=(
    "magic:magic.Dockerfile"
    "oletools:oletools.Dockerfile"
    "pdfid:pdfid.Dockerfile"
    "pymupdf:pymupdf.Dockerfile"
    "tesseract:tesseract.Dockerfile"
    "yara:yara.Dockerfile"
    "ioc-finder:ioc_finder.Dockerfile"
    "markitdown:markitdown.Dockerfile"
)

for entry in "${IMAGES[@]}"; do
    name="${entry%%:*}"
    dockerfile="${entry##*:}"
    image="attijari-extract-${name}"
    echo ""
    echo "--- Building ${image} from ${dockerfile} ---"
    docker build -t "${image}" -f "${dockerfile}" . && \
        echo "[OK] ${image}" || \
        echo "[FAIL] ${image}"
done

echo ""
echo "=== Build complete ==="
docker images --filter "reference=attijari-extract-*" --format "table {{.Repository}}\t{{.Size}}\t{{.CreatedSince}}"
