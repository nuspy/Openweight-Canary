#!/usr/bin/env sh
# Qwen 3.8 analysis after the Cohere report. Nothing starts until you run this file, and it needs a model server you start yourself.
# Usage: ./run-analysis.sh fetch | first | follow | tokens | report | all   [options of run.py, e.g. --url http://127.0.0.1:7232 --n 50]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if command -v python3 >/dev/null 2>&1; then py=python3
elif command -v python >/dev/null 2>&1; then py=python
else echo "Python 3.10 or later was not found in PATH" >&2; exit 1; fi
if [ "$#" -lt 1 ]; then
  echo "usage: $0 fetch|first|follow|tokens|report|all [run.py options]" >&2
  echo "       $py $here/run.py --help   for the options" >&2
  exit 2
fi
exec "$py" "$here/run.py" "$@"
