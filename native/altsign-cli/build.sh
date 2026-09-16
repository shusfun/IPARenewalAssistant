#!/bin/bash
#
# build.sh — AltSign CLI 编译脚本
# 构建阶段需要 macOS SDK 与 OpenSSL 头文件/库；运行时库会随应用一起分发。
#

set -eo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
case "${TARGET_ARCH:-$(uname -m)}" in
  amd64|x86_64) TARGET_ARCH="x86_64" ;;
  arm64|aarch64) TARGET_ARCH="arm64" ;;
  *)
    echo "unsupported TARGET_ARCH: ${TARGET_ARCH:-$(uname -m)}" >&2
    exit 1
    ;;
esac
export TARGET_ARCH
OPENSSL_PREFIX="$("$ROOT/scripts/openssl-prefix.sh")"
export OPENSSL_PREFIX

OUTPUT="${OUTPUT:-altsign-cli}"
mkdir -p "$(dirname "$OUTPUT")"
SDK_PATH="${SDKROOT:-}"
SYSROOT_FLAGS=()
ARCH_FLAGS=(-arch "$TARGET_ARCH")
if [ -n "$SDK_PATH" ]; then SYSROOT_FLAGS=(-isysroot "$SDK_PATH"); fi
CORECRYPTO_DIR="Dependencies"

if [ ! -d "${CORECRYPTO_DIR}" ]; then
    echo "Missing ${CORECRYPTO_DIR}/ccsrp.m."
    exit 1
fi

echo "============================================"
echo " Building AltSign CLI"
echo " Arch: ${TARGET_ARCH}"
echo " OpenSSL: ${OPENSSL_PREFIX}"
echo " SDK: ${SDK_PATH}"
echo " Output: ${OUTPUT}"
echo "============================================"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/corecrypto"
for header in Dependencies/*.h; do
    ln -s "$(pwd)/${header}" "${TMP_DIR}/corecrypto/$(basename "${header}")"
done

clang -ObjC -fobjc-arc \
    "${ARCH_FLAGS[@]}" \
    -DCORECRYPTO_DONOT_USE_TRANSPARENT_UNION \
    -I"${TMP_DIR}" -I"Dependencies" \
    "${SYSROOT_FLAGS[@]}" \
    -c "${CORECRYPTO_DIR}/ccsrp.m" \
    -o "${TMP_DIR}/ccsrp.o"

clang++ -std=c++17 -ObjC++ -fobjc-arc \
    "${ARCH_FLAGS[@]}" \
    -Wall -Wextra \
    -Wno-deprecated-declarations \
    -Wno-unused-parameter \
    -DCORECRYPTO_DONOT_USE_TRANSPARENT_UNION \
    "${SYSROOT_FLAGS[@]}" \
    -framework Foundation \
    -framework Security \
    -framework CoreFoundation \
    -framework CFNetwork \
    -I"${OPENSSL_PREFIX}/include" \
    -I"${TMP_DIR}" -I"Dependencies" \
    -L"${OPENSSL_PREFIX}/lib" \
    ${SDK_PATH:+-L"${SDK_PATH}/usr/lib/system"} \
    -lssl -lcrypto \
    -o "${OUTPUT}" \
    main.mm \
    anisette.mm \
    srp_auth.mm \
    apple_api.mm \
    certificate_request.mm \
    signer.mm \
    keychain.mm \
    "${TMP_DIR}/ccsrp.o"

if [[ "$OUTPUT" == /* ]]; then
    SIGN_BIN="$OUTPUT"
else
    SIGN_BIN="$(pwd)/$OUTPUT"
fi
SIGN_HELPER="$ROOT/scripts/sign-altsign-cli.sh"
if [ -f "${SIGN_HELPER}" ]; then
    /bin/bash "${SIGN_HELPER}" "$SIGN_BIN" || true
fi

echo "============================================"
echo " ✅ Build successful: ${SIGN_BIN}"
echo "============================================"
echo ""
echo "Usage:"
echo "  ./${OUTPUT} list --apple-id user@example.com"
echo "  ./${OUTPUT} sign --udid 00008030-000000000000 --ipa ./MyApp.ipa"
echo "  ./${OUTPUT} sign --udid 00008030-000000000000 \\"
echo "                   --app ./MyApp.app --output ./MyApp_signed.ipa"
