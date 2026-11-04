#!/usr/bin/env sh
# Starts the MalWeight Canary (Openweight Canary) page. Nothing is started until you run this file.
# Usage: ./run-canary.sh [config-file] [port]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
config=${1:-canary.json}
port=${2:-8765}
if [ "$port" = "8080" ]; then echo "port 8080 is not allowed; choose another" >&2; exit 1; fi
if command -v python3 >/dev/null 2>&1; then py=python3
elif command -v python >/dev/null 2>&1; then py=python
else echo "Python 3.10 or later was not found in PATH" >&2; exit 1; fi
export PYTHONPATH="$here"
cd "$here"
if [ ! -f "$config" ]; then
  echo "No $config yet: writing a starting one."
  "$py" -m canary init --dir "$(dirname "$config")"
fi
exec "$py" -m canary gui -c "$config" --port "$port"
