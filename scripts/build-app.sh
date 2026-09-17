#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-1.0.1}"
APP_NAME="续签助手.app"

fail() {
  print -u2 -- "$*"
  exit 1
}

usage() {
  fail "usage: $0 amd64|arm64"
}

case "${1:-}" in
  amd64|x86_64)
    GOARCH="amd64"
    TARGET_ARCH="x86_64"
    ;;
  arm64|aarch64)
    GOARCH="arm64"
    TARGET_ARCH="arm64"
    ;;
  *)
    usage
    ;;
esac
export TARGET_ARCH

host_arch="$(uname -m)"
if [[ "$TARGET_ARCH" != "$host_arch" ]]; then
  print -- "交叉构建 $TARGET_ARCH（当前宿主是 $host_arch）。OpenSSL 必须已是目标架构。"
fi

OPENSSL_PREFIX="$("$ROOT/scripts/openssl-prefix.sh")"
export OPENSSL_PREFIX

command -v clang >/dev/null || fail "缺少 clang，无法构建签名组件。"
command -v go >/dev/null || fail "缺少 Go 工具链。"
command -v npm >/dev/null || fail "缺少 npm。"

export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.1}"
SDKROOT="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)}"
[[ -n "$SDKROOT" && -d "$SDKROOT" ]] || fail "缺少 macOS SDK。"
export SDKROOT

if [[ ! -x "$ROOT/.tools/wails" ]]; then
  print -- "正在安装项目侧 Wails v2.12.0…"
  GOBIN="$ROOT/.tools" go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
fi
wails_version="$("$ROOT/.tools/wails" version 2>/dev/null || true)"
if [[ "$wails_version" != *v2.12.0* && "$wails_version" != *2.12.0* ]]; then
  print -- "Wails CLI 版本不是 v2.12.0，正在重装项目侧工具…"
  GOBIN="$ROOT/.tools" go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
fi

export CGO_ENABLED=1
export GOOS=darwin
export GOARCH
if [[ "$TARGET_ARCH" != "$host_arch" ]]; then
  export CGO_CFLAGS="${CGO_CFLAGS:-} -arch $TARGET_ARCH"
  export CGO_LDFLAGS="${CGO_LDFLAGS:-} -arch $TARGET_ARCH"
fi

WAILS_APP="$ROOT/build/bin/$APP_NAME"
ARCH_DIR="$ROOT/build/bin/darwin-$GOARCH"
PRESERVE="$(mktemp -d "${TMPDIR:-/tmp}/iparenewal-arch.XXXXXX")"
restore_arch_dirs() {
  mkdir -p "$ROOT/build/bin"
  for sibling in "$PRESERVE"/darwin-*(N); do
    [[ -d "$sibling" ]] || continue
    mv "$sibling" "$ROOT/build/bin/"
  done
  rmdir "$PRESERVE" 2>/dev/null || true
}
trap restore_arch_dirs EXIT

mkdir -p "$ROOT/build/bin"
for sibling in "$ROOT/build/bin"/darwin-*(N); do
  [[ -d "$sibling" ]] || continue
  mv "$sibling" "$PRESERVE/"
done

print -- "正在构建 darwin/$GOARCH 主程序…"
export PATH="$ROOT/.tools:$PATH"
cd "$ROOT"
"$ROOT/.tools/wails" build -clean -platform "darwin/$GOARCH"
[[ -d "$WAILS_APP" ]] || fail "Wails 未生成 $WAILS_APP"

trap - EXIT
restore_arch_dirs
rm -rf "$ARCH_DIR"
mkdir -p "$ARCH_DIR"
mv "$WAILS_APP" "$ARCH_DIR/$APP_NAME"

APP="$ARCH_DIR/$APP_NAME"
"$ROOT/scripts/build-signer.sh" "$APP"
codesign --force --sign - "$APP"

MAIN_BIN="$APP/Contents/MacOS/续签助手"
[[ -f "$MAIN_BIN" ]] || fail "缺少主程序：$MAIN_BIN"
main_arch="$(lipo -archs "$MAIN_BIN")"
if [[ "$main_arch" != "$TARGET_ARCH" ]]; then
  fail "主程序架构是 ${main_arch}，需要薄架构 ${TARGET_ARCH}"
fi

DMG_NAME="IPARenewalAssistant-v${VERSION}-macos-${GOARCH}.dmg"
DMG_PATH="$ARCH_DIR/$DMG_NAME"
"$ROOT/scripts/package-dmg.sh" "$APP" "$DMG_PATH"
print -- "安装包：$APP"
print -- "DMG：$DMG_PATH"
print -- "架构：$TARGET_ARCH OpenSSL：$OPENSSL_PREFIX"
