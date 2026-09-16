#!/bin/zsh
# Create GitHub release vX.Y.Z only when both thin architecture zips exist.
# Does not build packages and does not skip ARM64.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-0.1.0}"
TAG="v${VERSION}"
REPO="${GITHUB_REPO:-shusfun/IPARenewalAssistant}"
APP_NAME="续签助手.app"

fail() {
  print -u2 -- "$*"
  exit 1
}

amd64_zip="$ROOT/build/bin/darwin-amd64/IPARenewalAssistant-${TAG}-macos-amd64.zip"
arm64_zip="$ROOT/build/bin/darwin-arm64/IPARenewalAssistant-${TAG}-macos-arm64.zip"

[[ -f "$amd64_zip" ]] || fail "缺少 Intel 包：$amd64_zip"
[[ -f "$arm64_zip" ]] || fail "缺少 Apple Silicon 包：$arm64_zip。请在 M 芯片 Mac 上运行 ./scripts/build-app.sh arm64，完成真机验收后再发版。"

verify_app() {
  local app="$1"
  local want="$2"
  local res="$app/Contents/Resources"
  local main="$app/Contents/MacOS/续签助手"
  [[ -x "$main" ]] || fail "缺少主程序：$main"
  [[ -x "$res/altsign-cli" ]] || fail "安装包未包含签名器：$app"
  [[ -f "$res/libssl.3.dylib" && -f "$res/libcrypto.3.dylib" ]] || fail "安装包未包含 OpenSSL：$app"
  local file
  for file in "$main" "$res/altsign-cli" "$res/libssl.3.dylib" "$res/libcrypto.3.dylib"; do
    local archs
    archs="$(lipo -archs "$file")"
    if [[ "$archs" != "$want" ]]; then
      fail "$file 架构是 ${archs}，需要薄架构 ${want}"
    fi
  done
  if otool -L "$res/altsign-cli" | grep -E '/usr/local/opt/openssl|/opt/homebrew/opt/openssl|/Cellar/openssl' >/dev/null; then
    fail "$res/altsign-cli 仍依赖 Homebrew OpenSSL"
  fi
}

amd64_app="$ROOT/build/bin/darwin-amd64/$APP_NAME"
arm64_app="$ROOT/build/bin/darwin-arm64/$APP_NAME"
[[ -d "$amd64_app" ]] && verify_app "$amd64_app" x86_64
[[ -d "$arm64_app" ]] && verify_app "$arm64_app" arm64
[[ -d "$arm64_app" ]] || fail "缺少 Apple Silicon .app：$arm64_app。zip 存在但未提供可核验的安装包。"

if [[ "$(uname -m)" != "arm64" ]]; then
  fail "请在 M 芯片 Mac 上发版：本机是 $(uname -m)，无法核验 ARM64 真机验收是否已完成。"
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/iparenewal-release.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT
cp "$amd64_zip" "$arm64_zip" "$WORKDIR/"
(
  cd "$WORKDIR"
  shasum -a 256 IPARenewalAssistant-${TAG}-macos-amd64.zip IPARenewalAssistant-${TAG}-macos-arm64.zip > SHA256SUMS.txt
)

NOTES="$WORKDIR/notes.md"
cat > "$NOTES" <<EOF
续签助手 ${TAG}

两个独立薄架构安装包，不是 Universal。目标机不必安装 Homebrew OpenSSL。

- \`IPARenewalAssistant-${TAG}-macos-amd64.zip\`：Intel
- \`IPARenewalAssistant-${TAG}-macos-arm64.zip\`：Apple Silicon

仍需连接 UUID 匹配的 980Pro。未连接时只能查看历史，这与芯片无关。

ARM64 包已在 M 芯片真机完成登录、钥匙串授权、证书私钥复用、签名和设备安装验收。
EOF

command -v gh >/dev/null || fail "缺少 gh，无法发版。"
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  fail "Release $TAG 已存在：$REPO"
fi

gh release create "$TAG" \
  --repo "$REPO" \
  --title "续签助手 ${TAG}" \
  --notes-file "$NOTES" \
  "$WORKDIR/IPARenewalAssistant-${TAG}-macos-amd64.zip" \
  "$WORKDIR/IPARenewalAssistant-${TAG}-macos-arm64.zip" \
  "$WORKDIR/SHA256SUMS.txt"

view="$(gh release view "$TAG" --repo "$REPO" --json tagName,isDraft,isPrerelease,assets)"
print -- "$view"
print -- "$view" | grep -q "\"tagName\":\"${TAG}\"" || fail "发版后未看到 tag $TAG"
print -- "$view" | grep -q "IPARenewalAssistant-${TAG}-macos-amd64.zip" || fail "缺少 amd64 zip 资产"
print -- "$view" | grep -q "IPARenewalAssistant-${TAG}-macos-arm64.zip" || fail "缺少 arm64 zip 资产"
print -- "$view" | grep -q "SHA256SUMS.txt" || fail "缺少 SHA256SUMS.txt"
print -- "已发布 https://github.com/${REPO}/releases/tag/${TAG}"
