#!/bin/bash
set -e

echo "[*] Setting up Ruijie Portal Tool..."

# Create venv if not exists
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[*] Installing dependencies..."
venv/bin/pip install -r requirements.txt

# Create a wrapper script for easy execution
cat > ruijie << 'WRAPPER'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/venv/bin/python" "$DIR/ruijie.py" "$@"
WRAPPER
chmod +x ruijie

echo "[+] Setup complete!"
echo ""
echo "Usage: ./ruijie <command>"
echo ""
echo "  ./ruijie secret <code>   - Decrypt secret code"
echo "  ./ruijie login <voucher> - Login to portal"
echo "  ./ruijie monitor         - Watch & auto-reconnect"
echo "  ./ruijie status          - Check connection"
echo "  ./ruijie logout          - Logout"
