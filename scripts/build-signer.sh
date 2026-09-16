#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-}"
if [[ -z "$APP" || ! -d "$APP" ]]; then
  print -u2 -- "usage: $0 /path/to/续签助手.app"
  exit 1
fi

case "${TARGET_ARCH:-$(uname -m)}" in
  amd64|x86_64) TARGET_ARCH="x86_64" ;;
  arm64|aarch64) TARGET_ARCH="arm64" ;;
  *)
    print -u2 -- "unsupported TARGET_ARCH: ${TARGET_ARCH:-$(uname -m)}"
    exit 1
    ;;
esac
export TARGET_ARCH
OPENSSL_PREFIX="$("$ROOT/scripts/openssl-prefix.sh")"
export OPENSSL_PREFIX

SDKROOT="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)}"
if [[ -z "$SDKROOT" || ! -d "$SDKROOT" ]]; then
  print -u2 -- "缺少 macOS SDK，无法构建签名组件。"
  exit 1
fi
export SDKROOT

RESOURCES="$APP/Contents/Resources"
if [[ ! -d "$APP/Contents" ]]; then
  print -u2 -- "not a macOS app bundle: $APP"
  exit 1
fi
mkdir -p "$RESOURCES/wwdr"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/iparenewal-signer.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

print -- "正在构建 $TARGET_ARCH 签名器…"
(
  cd "$ROOT/native/altsign-cli"
  OUTPUT="$WORKDIR/altsign-cli" ./build.sh
)
if [[ ! -x "$WORKDIR/altsign-cli" ]]; then
  print -u2 -- "签名组件构建失败。"
  exit 1
fi

chmod u+w "$RESOURCES"/*(N) 2>/dev/null || true
cp "$WORKDIR/altsign-cli" "$RESOURCES/altsign-cli"
chmod 755 "$RESOURCES/altsign-cli"

wwdr_certs=("$ROOT/native/altsign-cli/wwdr/"*.cer(N))
if (( ${#wwdr_certs[@]} == 0 )); then
  print -u2 -- "缺少 WWDR 证书。"
  exit 1
fi
cp "$wwdr_certs[@]" "$RESOURCES/wwdr/"

for lib in libssl.3.dylib libcrypto.3.dylib; do
  src="$OPENSSL_PREFIX/lib/$lib"
  if [[ ! -f "$src" ]]; then
    print -u2 -- "缺少 OpenSSL 库：$src"
    exit 1
  fi
  chmod u+w "$RESOURCES/$lib" 2>/dev/null || true
  cp -L "$src" "$RESOURCES/$lib"
  chmod u+w "$RESOURCES/$lib"
  install_name_tool -id "@loader_path/$lib" "$RESOURCES/$lib"
done

rewrite_openssl_load_commands() {
  local file="$1"
  local old base
  while IFS= read -r old; do
    [[ -n "$old" ]] || continue
    base="${old:t}"
    case "$base" in
      libssl.3.dylib|libcrypto.3.dylib)
        if [[ "$old" != "@loader_path/$base" ]]; then
          install_name_tool -change "$old" "@loader_path/$base" "$file"
        fi
        ;;
    esac
  done < <(otool -L "$file" | tail -n +2 | awk '{print $1}')
}

rewrite_openssl_load_commands "$RESOURCES/altsign-cli"
rewrite_openssl_load_commands "$RESOURCES/libssl.3.dylib"
rewrite_openssl_load_commands "$RESOURCES/libcrypto.3.dylib"

if ! otool -l "$RESOURCES/altsign-cli" | grep -q '@loader_path'; then
  install_name_tool -add_rpath "@loader_path" "$RESOURCES/altsign-cli"
fi

assert_thin_arch() {
  local file="$1"
  local archs
  archs="$(lipo -archs "$file")"
  if [[ "$archs" != "$TARGET_ARCH" ]]; then
    print -u2 -- "$file 架构是 ${archs}，需要薄架构 ${TARGET_ARCH}"
    exit 1
  fi
}

assert_bundled_openssl() {
  local file="$1"
  if otool -L "$file" | grep -E '/usr/local/opt/openssl|/opt/homebrew/opt/openssl|/Cellar/openssl' >/dev/null; then
    print -u2 -- "$file 仍依赖 Homebrew OpenSSL："
    otool -L "$file" >&2
    exit 1
  fi
}

assert_thin_arch "$RESOURCES/altsign-cli"
assert_thin_arch "$RESOURCES/libssl.3.dylib"
assert_thin_arch "$RESOURCES/libcrypto.3.dylib"
assert_bundled_openssl "$RESOURCES/altsign-cli"
assert_bundled_openssl "$RESOURCES/libssl.3.dylib"
assert_bundled_openssl "$RESOURCES/libcrypto.3.dylib"

/bin/bash "$ROOT/scripts/sign-altsign-cli.sh" "$RESOURCES/altsign-cli" || true
if ! codesign --verify "$RESOURCES/altsign-cli" >/dev/null 2>&1; then
  codesign --force --sign - --identifier com.shus.iparenewalassistant.altsign-cli "$RESOURCES/altsign-cli"
fi
codesign --force --sign - "$RESOURCES/libssl.3.dylib"
codesign --force --sign - "$RESOURCES/libcrypto.3.dylib"
print -- "已嵌入签名器：$RESOURCES/altsign-cli"
