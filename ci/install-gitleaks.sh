#!/usr/bin/env bash
# gitleaks（秘密情報の検査）を入れる。版とチェックサム（SHA-256）を固定している。
# チェックサムが合わなければ、入れずに失敗する。
# 版を変えるときは、公開されているチェックサムの一覧（gitleaks_<版>_checksums.txt）と、
# 自分でダウンロードして計算した値の両方が一致することを確かめてから、下の2つを書き換える。
set -euo pipefail

version="8.30.1"
sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"  # gitleaks_8.30.1_linux_x64.tar.gz

work="${RUNNER_TEMP:-$(mktemp -d)}"
archive="$work/gitleaks.tar.gz"
curl --fail --silent --show-error --location --retry 3 \
  --output "$archive" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
echo "${sha256}  ${archive}" | sha256sum --check --strict

mkdir -p "$work/gitleaks-bin"
tar -xzf "$archive" -C "$work/gitleaks-bin" gitleaks
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$work/gitleaks-bin" >> "$GITHUB_PATH"
fi
"$work/gitleaks-bin/gitleaks" version
