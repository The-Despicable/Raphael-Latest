#!/usr/bin/env bash
# ============================================================
# Raphael 2.0 — Full Bootstrap
# Installs everything needed from a bare WSL/Ubuntu system.
# Run: bash bootstrap.sh 2>&1 | tee bootstrap.log
# ============================================================
set -euo pipefail

RAPHAEL_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$RAPHAEL_DIR"

echo "============================================"
echo " Raphael 2.0 Bootstrap"
echo " Target: $RAPHAEL_DIR"
echo "============================================"

# ──────────────────────────────────────────────
# 1. System Dependencies
# ──────────────────────────────────────────────
echo ""
echo "[1/8] Installing system dependencies..."

sudo apt-get update -qq
sudo apt-get install -y -qq \
    curl wget git jq ca-certificates openssl \
    tor netcat-openbsd dnsutils \
    wireguard \
    python3 python3-pip python3-venv \
    nmap \
    docker.io docker-compose-v2 \
    >/dev/null 2>&1 || {
    # fallback for docker
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io 2>/dev/null || true
}

sudo systemctl enable docker 2>/dev/null || true
sudo systemctl start docker 2>/dev/null || true

# ──────────────────────────────────────────────
# 2. Ollama
# ──────────────────────────────────────────────
echo "[2/8] Installing Ollama..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi

# ──────────────────────────────────────────────
# 3. Go (for tools like subfinder, nuclei on host)
# ──────────────────────────────────────────────
echo "[3/8] Installing Go..."
if ! command -v go &>/dev/null; then
    wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# ──────────────────────────────────────────────
# 4. Python Virtual Environment
# ──────────────────────────────────────────────
echo "[4/8] Setting up Python virtual environment..."
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -r requirements.txt

# ──────────────────────────────────────────────
# 5. Ollama Models (worm proxies to ollama.com)
# ──────────────────────────────────────────────
echo "[5/8] Pulling Ollama models (worm models proxy to ollama.com)..."
ollama pull blackgrg26/WORMGPT-13:latest 2>/dev/null || echo "  [SKIP] WORMGPT-13 (proxy model — will pull on first use)"
ollama pull minimax-m3:cloud 2>/dev/null || echo "  [SKIP] minimax-m3"
ollama pull bjoernb/gemma4-31b-think 2>/dev/null || echo "  [SKIP] gemma4"

# ──────────────────────────────────────────────
# 6. Environment Configuration
# ──────────────────────────────────────────────
echo "[6/8] Configuring environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo ""
    echo "  >>> EDIT .env with your API keys <<<"
    echo "  Minimum required: NVIDIA_API_KEY or OPENAI_API_KEY"
    echo "  nano .env"
else
    echo "  .env already exists — keeping current config"
fi

# ──────────────────────────────────────────────
# 7. Docker Build
# ──────────────────────────────────────────────
echo "[7/8] Building Docker images..."
echo "  (This takes 5-15 minutes on first run)"
docker compose build --parallel 2>&1 | tail -5 || echo "  [WARN] Docker build had issues — check docker compose build"

# ──────────────────────────────────────────────
# 8. Post-Setup Instructions
# ──────────────────────────────────────────────
echo ""
echo "============================================"
echo " Raphael 2.0 Bootstrap Complete"
echo "============================================"
echo ""
echo "  Next steps:"
echo "    1. Edit .env with your API keys:"
echo "       nano .env"
echo ""
echo "    2. Start Tor:"
echo "       sudo tor -f /etc/tor/torrc &"
echo "       sleep 5"
echo "       curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip"
echo ""
echo "    3. Apply kill switch (blocks all non-Tor traffic):"
echo "       sudo bash setup_killswitch.sh"
echo ""
echo "    4. Start Docker services:"
echo "       docker compose up -d"
echo ""
echo "    5. Activate Python venv and run:"
echo "       source .venv/bin/activate"
echo "       python orchestrator/app.py"
echo ""
echo "    6. Optional — HRM setup:"
echo "       bash start_hrm.sh"
echo ""
echo "  Full docs:"
echo "    - QUICKSTART.md     — quick reference"
echo "    - procedure.md      — mandatory OPSEC checks"
echo "    - ghost.md          — invisibility layer"
echo "    - docs/             — all project documentation"
echo "============================================"
