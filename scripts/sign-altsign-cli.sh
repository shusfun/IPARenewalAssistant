#!/bin/bash
# Sign altsign-cli with a reusable local codesigning identity.
# Does not enable hardened runtime, trust the cert system-wide, or allow all apps.

set -u

BIN="${1:-}"
IDENTITY_NAME="IPARenewalAssistant Helper"
IDENTIFIER="com.shus.iparenewalassistant.altsign-cli"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${OPENSSL_PREFIX:-}" ]; then
  OPENSSL_PREFIX="$("$SCRIPT_DIR/openssl-prefix.sh" 2>/dev/null || true)"
fi
if [ -n "${OPENSSL_PREFIX:-}" ] && [ -x "${OPENSSL_PREFIX}/bin/openssl" ]; then
  OPENSSL_BIN="${OPENSSL_PREFIX}/bin/openssl"
else
  OPENSSL_BIN=""
fi

if [ ! -f "$BIN" ]; then
  echo "sign-altsign-cli: missing binary ${BIN:-<(none)>}" >&2
  exit 0
fi

has_identity() {
  security find-identity -v -p codesigning 2>/dev/null | grep -F "$IDENTITY_NAME" >/dev/null
}

run_limited() {
  perl -e 'alarm shift; exec @ARGV' 20 "$@"
}

login_keychain() {
  if [ -f "$HOME/Library/Keychains/login.keychain-db" ]; then
    echo "$HOME/Library/Keychains/login.keychain-db"
  else
    echo "$HOME/Library/Keychains/login.keychain"
  fi
}

if ! has_identity; then
  if [ ! -x "$OPENSSL_BIN" ]; then
    OPENSSL_BIN="$(command -v openssl || true)"
  fi
  if [ -z "$OPENSSL_BIN" ] || [ ! -x "$OPENSSL_BIN" ]; then
    echo "sign-altsign-cli: no local helper identity and openssl is unavailable; leaving unsigned" >&2
    exit 0
  fi
  if [ -x /usr/bin/openssl ]; then
    PKCS12_BIN=/usr/bin/openssl
  else
    PKCS12_BIN="$OPENSSL_BIN"
  fi

  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/altsign-helper-cert.XXXXXX")"
  cleanup() { rm -rf "$WORKDIR"; }
  trap cleanup EXIT

  cat > "$WORKDIR/req.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_codesign
prompt = no
[req_distinguished_name]
CN = ${IDENTITY_NAME}
[v3_codesign]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
EOF

  if ! "$OPENSSL_BIN" req -new -newkey rsa:2048 -nodes -x509 -days 3650 \
      -config "$WORKDIR/req.cnf" \
      -keyout "$WORKDIR/key.pem" -out "$WORKDIR/cert.pem" >/dev/null 2>&1; then
    echo "sign-altsign-cli: could not create a local helper certificate; leaving unsigned" >&2
    exit 0
  fi
  if ! "$PKCS12_BIN" pkcs12 -export -inkey "$WORKDIR/key.pem" -in "$WORKDIR/cert.pem" \
      -out "$WORKDIR/ident.p12" -passout pass:temporary \
      -name "$IDENTITY_NAME" >/dev/null 2>&1; then
    echo "sign-altsign-cli: could not export the helper identity; leaving unsigned" >&2
    exit 0
  fi

  LOGIN_KC="$(login_keychain)"
  if ! run_limited /usr/bin/security import "$WORKDIR/ident.p12" -f pkcs12 -k "$LOGIN_KC" -P temporary \
      -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1; then
    echo "sign-altsign-cli: could not import the helper identity; leaving unsigned" >&2
    exit 0
  fi
  rm -rf "$WORKDIR"
  trap - EXIT

  if ! has_identity; then
    security delete-certificate -c "$IDENTITY_NAME" >/dev/null 2>&1 || true
    echo "sign-altsign-cli: helper certificate imported without a private key; leaving unsigned" >&2
    echo "sign-altsign-cli: run the build from Terminal once if macOS asks to allow adding this identity" >&2
    exit 0
  fi
fi

if ! run_limited /usr/bin/codesign --force --sign "$IDENTITY_NAME" --identifier "$IDENTIFIER" "$BIN" >/dev/null 2>&1; then
  echo "sign-altsign-cli: codesign failed; helper may still be unsigned" >&2
  exit 0
fi

exit 0
