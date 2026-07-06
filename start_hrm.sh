#!/bin/bash
# Start HRM microservice (standalone, outside Docker)
# Uses the HRM virtualenv with CPU torch

HRM_VENV="/home/yaser/Ultimate skill/HRM/.venv/bin/python"
PORT=${1:-9501}

if [ ! -f "$HRM_VENV" ]; then
    echo "HRM venv not found at $HRM_VENV"
    echo "Run: cd /home/yaser/Ultimate\ skill/HRM && python3 -m venv .venv && source .venv/bin/activate && pip install torch --extra-index-url https://download.pytorch.org/whl/cpu && pip install fastapi uvicorn pydantic pyyaml tqdm huggingface-hub"
    exit 1
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "Starting HRM microservice on port $PORT..."
exec "$HRM_VENV" -m orchestrator.hrm_service --port "$PORT"
