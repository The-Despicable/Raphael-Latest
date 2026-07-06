#!/bin/bash
set -e

INSTALL_DIR="$HOME/opencode-telegram-mcp"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  OpenCode Telegram MCP — Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Install Python deps
echo "[1/5] Installing Python dependencies..."
pip install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages -q
echo "      ✓ Done"

# 2. Load .env if it exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    echo "[2/5] Loading .env..."
    set -a; source "$SCRIPT_DIR/.env"; set +a
    echo "      ✓ Done"
else
    echo "[2/5] No .env found — copy .env.example to .env and fill in values"
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    echo "      Created .env — edit it now then re-run setup.sh"
    exit 1
fi

# 3. Validate env vars
echo "[3/5] Validating config..."
if [ -z "$TELEGRAM_TOKEN" ] || [ "$TELEGRAM_TOKEN" = "your_bot_token_here" ]; then
    echo "      ❌ TELEGRAM_TOKEN not set in .env"
    exit 1
fi
if [ -z "$TELEGRAM_CHAT_ID" ] || [ "$TELEGRAM_CHAT_ID" = "your_numeric_chat_id_here" ]; then
    echo "      ❌ TELEGRAM_CHAT_ID not set in .env"
    exit 1
fi
echo "      ✓ Token: ${TELEGRAM_TOKEN:0:10}..."
echo "      ✓ Chat ID: $TELEGRAM_CHAT_ID"

# 4. Generate OpenCode config
echo "[4/5] Generating OpenCode MCP config..."
OPENCODE_CONFIG="$HOME/.config/opencode/config.json"
mkdir -p "$(dirname $OPENCODE_CONFIG)"

# Check if config exists; if so, we need to merge
if [ -f "$OPENCODE_CONFIG" ]; then
    echo "      Found existing config at $OPENCODE_CONFIG"
    echo "      ⚠️  Add this block to your config manually:"
    echo '      "mcp": {'
    echo '        "opencode-telegram": {'
    echo "          \"command\": \"python3\","
    echo "          \"args\": [\"$SCRIPT_DIR/mcp_server.py\"],"
    echo '          "env": {'
    echo "            \"TELEGRAM_TOKEN\": \"$TELEGRAM_TOKEN\","
    echo "            \"TELEGRAM_CHAT_ID\": \"$TELEGRAM_CHAT_ID\","
    echo "            \"WORK_DIR\": \"${WORK_DIR:-$HOME}\""
    echo '          }'
    echo '        }'
    echo '      }'
else
    # Write fresh config
    cat > "$OPENCODE_CONFIG" <<JSON
{
  "\$schema": "https://opencode.ai/config.json",
  "mcp": {
    "opencode-telegram": {
      "command": "python3",
      "args": ["$SCRIPT_DIR/mcp_server.py"],
      "env": {
        "TELEGRAM_TOKEN": "$TELEGRAM_TOKEN",
        "TELEGRAM_CHAT_ID": "$TELEGRAM_CHAT_ID",
        "WORK_DIR": "${WORK_DIR:-$HOME}"
      },
      "enabled": true
    }
  }
}
JSON
    echo "      ✓ Config written to $OPENCODE_CONFIG"
fi

# 5. Create systemd service for bot (WSL2-compatible via .profile)
echo "[5/5] Creating startup entry..."
SERVICE_LINE="python3 $SCRIPT_DIR/telegram_bot.py &"
PROFILE="$HOME/.bashrc"

if ! grep -q "telegram_bot.py" "$PROFILE"; then
    cat >> "$PROFILE" <<EOF

# OpenCode Telegram Bot (auto-started)
if ! pgrep -f "telegram_bot.py" > /dev/null; then
    source $SCRIPT_DIR/.env && python3 $SCRIPT_DIR/telegram_bot.py >> $SCRIPT_DIR/bot.log 2>&1 &
fi
EOF
    echo "      ✓ Bot will auto-start with new WSL sessions"
else
    echo "      ✓ Auto-start already configured"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Setup complete!"
echo ""
echo "  Start the bot now:"
echo "  source .env && python3 telegram_bot.py"
echo ""
echo "  Then message your bot on Telegram: /start"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
