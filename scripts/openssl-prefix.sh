#!/bin/bash
# Resolve an OpenSSL 3 prefix whose libraries match TARGET_ARCH.
# Prints the prefix to stdout. Does not assume Homebrew's Intel path.
#
# TARGET_ARCH: x86_64 or arm64 (amd64 is accepted as x86_64).
# OPENSSL_PREFIX: if set, only validated, never replaced.

set -euo pipefail

normalize_arch() {
  case "$1" in
    amd64|x86_64) echo x86_64 ;;
    arm64|aarch64) echo arm64 ;;
    *)
      echo "unsupported TARGET_ARCH: $1" >&2
      return 1
      ;;
  esac
}

target_arch="$(normalize_arch "${TARGET_ARCH:-${1:-$(uname -m)}}")"

dylib_has_arch() {
  local file="$1"
  local archs
  archs="$(lipo -archs "$file" 2>/dev/null || true)"
  [[ " $archs " == *" $target_arch "* ]]
}

valid_prefix() {
  local prefix="$1"
  [[ -d "$prefix/include/openssl" ]] || return 1
  [[ -f "$prefix/lib/libssl.3.dylib" ]] || return 1
  [[ -f "$prefix/lib/libcrypto.3.dylib" ]] || return 1
  dylib_has_arch "$prefix/lib/libssl.3.dylib" || return 1
  dylib_has_arch "$prefix/lib/libcrypto.3.dylib" || return 1
  return 0
}

fail_prefix() {
  local prefix="$1"
  echo "OpenSSL prefix is not usable for $target_arch: $prefix" >&2
  echo "Need include/openssl, libssl.3.dylib, libcrypto.3.dylib, and matching lipo arch." >&2
  exit 1
}

if [[ -n "${OPENSSL_PREFIX:-}" ]]; then
  valid_prefix "$OPENSSL_PREFIX" || fail_prefix "$OPENSSL_PREFIX"
  printf '%s\n' "$OPENSSL_PREFIX"
  exit 0
fi

candidates=()
if command -v brew >/dev/null 2>&1; then
  brew_prefix="$(brew --prefix openssl@3 2>/dev/null || true)"
  if [[ -n "$brew_prefix" ]]; then
    candidates+=("$brew_prefix")
  fi
fi
candidates+=("/opt/homebrew/opt/openssl@3" "/usr/local/opt/openssl@3")

seen=" "
for prefix in "${candidates[@]}"; do
  [[ -n "$prefix" ]] || continue
  [[ "$seen" == *" $prefix "* ]] && continue
  seen+=" $prefix "
  if valid_prefix "$prefix"; then
    printf '%s\n' "$prefix"
    exit 0
  fi
done

echo "No OpenSSL 3 prefix found for $target_arch. Set OPENSSL_PREFIX to a matching prefix." >&2
exit 1
