#!/usr/bin/env bash
# Menjalankan seluruh pengujian ScanGuard.
#
# Di komputer dengan layar (Windows/Linux desktop):
#     ./run_tests.sh
#
# Di server tanpa layar, pengujian antarmuka butuh layar maya:
#     sudo apt install xvfb
#     xvfb-run -a ./run_tests.sh
#
# Pengujian yang memerlukan ClamAV akan dilewati otomatis bila ClamAV tidak
# terpasang, jadi skrip ini tetap bisa dijalankan di komputer mana pun.
set -u

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    PYTHON=python
fi

echo "Menggunakan: $("$PYTHON" --version)"

if [ -z "${DISPLAY:-}" ] && command -v xvfb-run >/dev/null 2>&1; then
    echo "Tidak ada layar terdeteksi - memakai xvfb-run untuk pengujian antarmuka."
    exec xvfb-run -a "$PYTHON" -m unittest discover -s tests -v
fi

exec "$PYTHON" -m unittest discover -s tests -v
