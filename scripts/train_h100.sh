#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
TRAIN_SECONDS="${TRAIN_SECONDS:-3600}"
OUTPUT_DIR="${1:-$PROJECT_ROOT/runs/jac-codebert}"
ARTIFACT_DIR="$PROJECT_ROOT/artifacts"
PIPELINE_DIR="$ARTIFACT_DIR/jac_codebert_pipeline_bundle"
DATA_DIR="$ARTIFACT_DIR/jac_vulnerability_dataset_v2_5000_bundle"
PIPELINE_FILE="$PIPELINE_DIR/jac_codebert_pipeline.py"
DATASET_FILE="$DATA_DIR/jac_vulnerability_dataset_v2_5000.csv"
BASE_MODEL_DIR="$ARTIFACT_DIR/models/codebert-base"

mkdir -p "$ARTIFACT_DIR" "$PROJECT_ROOT/runs"
"$PYTHON_BIN" -m zipfile -e \
    "$PROJECT_ROOT/jac_codebert_pipeline_bundle.zip" \
    "$ARTIFACT_DIR"
"$PYTHON_BIN" -m zipfile -e \
    "$PROJECT_ROOT/jac_vulnerability_dataset_v2_5000_bundle.zip" \
    "$ARTIFACT_DIR"

"$PYTHON_BIN" - <<'PY'
import torch

print("PyTorch:", torch.__version__)
print("CUDA available:", torch.cuda.is_available())
if not torch.cuda.is_available():
    raise SystemExit(
        "CUDA is unavailable. Select an H100 GPU image with CUDA-enabled PyTorch."
    )
print("GPU:", torch.cuda.get_device_name(0))
print("BF16 supported:", torch.cuda.is_bf16_supported())
PY

if [[ ! -f "$BASE_MODEL_DIR/config.json" ]]; then
    "$PYTHON_BIN" "$PIPELINE_FILE" cache \
        --output "$BASE_MODEL_DIR"
fi

SMOKE_DIR="$PROJECT_ROOT/runs/jac-codebert-smoke"
echo "Running the one-epoch classifier-head smoke test..."
"$PYTHON_BIN" "$PIPELINE_FILE" train \
    --dataset "$DATASET_FILE" \
    --base-model "$BASE_MODEL_DIR" \
    --local-files-only \
    --require-cuda \
    --repair-split \
    --output "$SMOKE_DIR" \
    --epochs 1 \
    --freeze-encoder \
    --max-length 256 \
    --train-batch-size 128 \
    --eval-batch-size 256 \
    --gradient-accumulation-steps 1

echo "Starting full fine-tuning with an optimizer-time cap of ${TRAIN_SECONDS}s..."
"$PYTHON_BIN" "$PIPELINE_FILE" train \
    --dataset "$DATASET_FILE" \
    --base-model "$BASE_MODEL_DIR" \
    --local-files-only \
    --require-cuda \
    --repair-split \
    --output "$OUTPUT_DIR" \
    --epochs 100 \
    --max-train-seconds "$TRAIN_SECONDS" \
    --early-stopping-patience 5 \
    --warmup-ratio 0.01 \
    --max-length 256 \
    --train-batch-size 64 \
    --eval-batch-size 128 \
    --gradient-accumulation-steps 1

RESULT_ARCHIVE="${OUTPUT_DIR}.results.tar.gz"
tar \
    --exclude='*/checkpoints' \
    -czf "$RESULT_ARCHIVE" \
    -C "$OUTPUT_DIR" \
    .

"$PYTHON_BIN" - "$OUTPUT_DIR/summary.json" <<'PY'
import json
import sys

summary = json.load(open(sys.argv[1], encoding="utf-8"))
print(json.dumps(summary, indent=2))
PY

echo "Model directory: $OUTPUT_DIR"
echo "Downloadable results archive: $RESULT_ARCHIVE"
