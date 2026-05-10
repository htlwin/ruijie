#!/bin/bash
set -e

echo "[*] Setting up Ruijie Portal Tool..."

if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[*] Installing dependencies..."
venv/bin/pip install -r requirements.txt

cat > ruijie << 'WRAPPER'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/venv/bin/python" "$DIR/ruijie.py" "$@"
WRAPPER
chmod +x ruijie

echo "[+] Setup complete!"
echo ""
echo "Usage: ./ruijie"
echo ""
echo "  ./ruijie                    - Run with defaults (5 threads, 0.1s interval)"
echo "  ./ruijie -t 10              - Use 10 ping threads"
echo "  ./ruijie -i 0.05            - Faster ping interval"
echo "  ./ruijie -c 888888          - Use custom access code"
