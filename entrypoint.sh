#!/bin/bash
set -e

CHROMA_PATH="${CHROMA_PATH:-/app/chroma_db_v2}"
COLLECTION_MARKER="${CHROMA_PATH}/.collection_ready"

echo "============================================"
echo "  LogGuard AI — Starting up"
echo "============================================"

# Build ChromaDB only if not already built
if [ ! -f "$COLLECTION_MARKER" ]; then
    echo ""
    echo "📦 ChromaDB collection not found — building now..."
    echo "   (This runs once and takes ~30 seconds)"
    echo ""

    python /app/build_chroma.py

    # Leave a marker so we skip this on future restarts
    touch "$COLLECTION_MARKER"

    echo ""
    echo "✅ ChromaDB ready."
else
    echo "✅ ChromaDB collection already exists — skipping build."
fi

echo ""
echo "🚀 Starting Streamlit..."
echo "============================================"

exec streamlit run app.py \
    --server.port=8501 \
    --server.address=0.0.0.0
