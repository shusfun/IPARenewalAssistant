#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE_ROOT="${IPARENEWAL_CACHE:-$HOME/Library/Caches/com.shus.iparenewalassistant}"
TARGET_ARCH="$(uname -m)"
export TARGET_ARCH
OPENSSL_PREFIX="$("$ROOT/scripts/openssl-prefix.sh")"
KEYCHAIN_CACHE="${HOME}/Library/Caches/com.shus.iparenewalassistant/keychains"

fail() {
  print -u2 -- "$*"
  exit 1
}

command -v clang >/dev/null || fail "缺少 clang，无法构建签名组件。"
command -v go >/dev/null || fail "缺少 Go 工具链。"
command -v npm >/dev/null || fail "缺少 npm，无法启动前端热更新。"

# Wails v2.12.0 无法分析 Go 1.27 的标准库类型信息；开发入口固定使用 go.mod 中的 1.26.1。
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.1}"

if [[ ! -d "$OPENSSL_PREFIX/include/openssl" ]]; then
  fail "缺少 OpenSSL 头文件：$OPENSSL_PREFIX"
fi
if [[ ! -e "$OPENSSL_PREFIX/lib/libssl.dylib" && ! -e "$OPENSSL_PREFIX/lib/libssl.3.dylib" ]]; then
  fail "缺少 OpenSSL 库：$OPENSSL_PREFIX"
fi

SDKROOT="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)}"
if [[ -z "$SDKROOT" || ! -d "$SDKROOT" ]]; then
  fail "缺少 macOS SDK，无法构建签名组件。"
fi
export SDKROOT OPENSSL_PREFIX

mkdir -p "$CACHE_ROOT/work" "$CACHE_ROOT/go-build" "$ROOT/.tools"
export GOCACHE="$CACHE_ROOT/go-build"
export IPARENEWAL_WORK_DIR="$CACHE_ROOT/work"
unset TMPDIR

if [[ ! -x "$ROOT/.tools/wails" ]]; then
  print -- "正在安装项目侧 Wails v2.12.0…"
  GOBIN="$ROOT/.tools" go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
fi
wails_version="$("$ROOT/.tools/wails" version 2>/dev/null || true)"
if [[ "$wails_version" != *v2.12.0* && "$wails_version" != *2.12.0* ]]; then
  print -- "Wails CLI 版本不是 v2.12.0，正在重装项目侧工具…"
  GOBIN="$ROOT/.tools" go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
fi

print -- "正在构建原生签名器…"
(
  cd "$ROOT/native/altsign-cli"
  ./build.sh
)
export IPARENEWAL_SIGNER="$ROOT/native/altsign-cli/altsign-cli"
if [[ ! -x "$IPARENEWAL_SIGNER" ]]; then
  fail "签名组件构建失败。"
fi

cleanup() {
  if [[ -d "$KEYCHAIN_CACHE" ]]; then
    find "$KEYCHAIN_CACHE" -maxdepth 1 -type f -name '*.keychain-db' -delete 2>/dev/null || true
  fi
  find "$IPARENEWAL_WORK_DIR" -maxdepth 1 -type d -name '*-*-*-*-*' -exec rm -rf {} + 2>/dev/null || true
}
trap cleanup EXIT INT TERM

export PATH="$ROOT/.tools:$PATH"
print -- "签名器：$IPARENEWAL_SIGNER"
print -- "启动 Wails 开发界面…"
cd "$ROOT"
"$ROOT/.tools/wails" dev
