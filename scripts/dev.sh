#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED_VOLUME="/Volumes/980Pro"
EXPECTED_VOLUME_UUID="26CAAB44-4990-4003-9F28-D4FB791D33D1"
CACHE_ROOT="/Volumes/980Pro/Cache/IPARenewalAssistant"
TARGET_ARCH="$(uname -m)"
export TARGET_ARCH
OPENSSL_PREFIX="$("$ROOT/scripts/openssl-prefix.sh")"
KEYCHAIN_CACHE="${HOME}/Library/Caches/com.shus.iparenewalassistant/keychains"

fail() {
  print -u2 -- "$*"
  exit 1
}

if [[ ! -d "$EXPECTED_VOLUME" ]]; then
  fail "980Pro 未连接，开发入口不会改用内置盘。"
fi

volume_plist="$(diskutil info -plist "$EXPECTED_VOLUME" 2>/dev/null)" || fail "无法核验 980Pro 身份。"
volume_uuid="$(print -r -- "$volume_plist" | plutil -extract VolumeUUID raw - 2>/dev/null)" || fail "无法读取 980Pro 卷 UUID。"
if [[ "${volume_uuid:u}" != "${EXPECTED_VOLUME_UUID:u}" ]]; then
  fail "980Pro 卷身份不符，开发入口已停止。"
fi

probe="$(mktemp "$EXPECTED_VOLUME/.iparenewal-dev-write-XXXXXX")" || fail "980Pro 当前不可写，开发入口已停止。"
rm -f "$probe"

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
