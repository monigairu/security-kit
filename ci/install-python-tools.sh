#!/usr/bin/env bash
# キット自体の CI で使う Python の道具（Ruff、uv、zizmor）を入れる。
# 版とハッシュは ci/requirements.txt で固定している。ハッシュが合わないものは入らない。
set -euo pipefail

cd "$(dirname "$0")/.."
venv="${RUNNER_TEMP:-$(mktemp -d)}/kit-ci-venv"
python3 -m venv "$venv"
"$venv/bin/python" -m pip install --quiet --require-hashes --no-deps --disable-pip-version-check \
  -r ci/requirements.txt
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$venv/bin" >> "$GITHUB_PATH"
fi
echo "入れた道具: $("$venv/bin/ruff" --version)、$("$venv/bin/uv" --version)、$("$venv/bin/zizmor" --version)"
