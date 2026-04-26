#!/usr/bin/env bash
#
# Regenerate Snippy test fixtures using openssl.
#
# Usage:
#   test/support/gen_fixtures.sh [TARGET_DIR]
#
# If TARGET_DIR is omitted, fixtures are written to a tempdir whose path is
# printed on stdout. Snippy.TestFixtures invokes this script automatically on
# every test run; you should rarely need to run it by hand.
#
# Requirements: openssl >= 3.0 (uses -copy_extensions and -not_before/-not_after)
#
# Files produced (in TARGET_DIR):
#   ca.pem            self-signed root CA cert
#   ca.key            root CA private key (RSA, unencrypted)
#   a.pem  / a.key    RSA leaf for "a.example.com" (unencrypted)
#   b.pem  / b.key    RSA leaf for "b.example.com" (unencrypted)
#   b.enc.key         same key as b.key, encrypted with passphrase "secret"
#   wild.pem / wild.key   RSA leaf SAN=*.wild.example.com
#   ec.pem  / ec.key      ECDSA leaf for "ec.example.com"
#   expired.pem / expired.key   RSA leaf, notAfter=1 day ago
#   future.pem  / future.key    RSA leaf, notBefore=1 year from now
#   pwd.txt           file containing "secret\n"        (for _PWD_FILE)
#   pwd_notrim.txt    file containing "secret" no LF    (trim-fallback test)

set -euo pipefail

DIR="${1:-$(mktemp -d -t snippy_fixtures.XXXXXX)}"
mkdir -p "$DIR"
cd "$DIR"

OPENSSL="${OPENSSL:-openssl}"
PASS="secret"

# ---- 1. Root CA -------------------------------------------------------------

"$OPENSSL" req -x509 -newkey rsa:2048 -nodes \
  -keyout ca.key -out ca.pem \
  -days 3650 \
  -subj "/CN=Snippy Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  >/dev/null 2>&1

# Helper: issue an RSA leaf cert signed by the CA.
#   $1 logical name (subject CN + dNSName SAN; also stem of output filenames)
#   $2 file basename (without extension)
issue_rsa_leaf() {
  local cn="$1"
  local stem="$2"
  "$OPENSSL" req -new -newkey rsa:2048 -nodes \
    -keyout "${stem}.key" -out "${stem}.csr" \
    -subj "/CN=${cn}" \
    -addext "subjectAltName=DNS:${cn}" \
    >/dev/null 2>&1
  "$OPENSSL" x509 -req -in "${stem}.csr" \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out "${stem}.pem" -days 365 \
    -copy_extensions copy \
    >/dev/null 2>&1
  rm -f "${stem}.csr"
}

# Same as above but with explicit notBefore/notAfter (RFC 5280 generalTime).
# $1 cn, $2 stem, $3 not_before (YYYYMMDDhhmmssZ), $4 not_after
issue_rsa_leaf_dated() {
  local cn="$1" stem="$2" nb="$3" na="$4"
  "$OPENSSL" req -new -newkey rsa:2048 -nodes \
    -keyout "${stem}.key" -out "${stem}.csr" \
    -subj "/CN=${cn}" \
    -addext "subjectAltName=DNS:${cn}" \
    >/dev/null 2>&1
  "$OPENSSL" x509 -req -in "${stem}.csr" \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out "${stem}.pem" \
    -not_before "$nb" -not_after "$na" \
    -copy_extensions copy \
    >/dev/null 2>&1
  rm -f "${stem}.csr"
}

# ---- 2. Standard RSA leaves -------------------------------------------------

issue_rsa_leaf "a.example.com" "a"
issue_rsa_leaf "b.example.com" "b"

# ---- 3. ECDSA leaf ----------------------------------------------------------

"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out ec.key
"$OPENSSL" req -new -key ec.key -out ec.csr \
  -subj "/CN=ec.example.com" \
  -addext "subjectAltName=DNS:ec.example.com" \
  >/dev/null 2>&1
"$OPENSSL" x509 -req -in ec.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out ec.pem -days 365 \
  -copy_extensions copy \
  >/dev/null 2>&1
rm -f ec.csr

# ---- 4. Wildcard SAN --------------------------------------------------------

"$OPENSSL" req -new -newkey rsa:2048 -nodes \
  -keyout wild.key -out wild.csr \
  -subj "/CN=wild.example.com" \
  -addext "subjectAltName=DNS:*.wild.example.com" \
  >/dev/null 2>&1
"$OPENSSL" x509 -req -in wild.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out wild.pem -days 365 \
  -copy_extensions copy \
  >/dev/null 2>&1
rm -f wild.csr

# ---- 5. Expired and future leaves -------------------------------------------

# Date math is portable enough between BSD and GNU date; we precompute.
gen_date() {
  # $1 = offset in seconds from now (may be negative)
  if date -u -d "now" +%s >/dev/null 2>&1; then
    # GNU date
    date -u -d "@$(($(date -u +%s) + $1))" +"%Y%m%d%H%M%SZ"
  else
    # BSD date (macOS)
    date -u -j -f "%s" "$(($(date -u +%s) + $1))" +"%Y%m%d%H%M%SZ"
  fi
}

NB_EXPIRED="$(gen_date $((-2 * 365 * 86400)))"      # 2 years ago
NA_EXPIRED="$(gen_date -86400)"                      # 1 day ago
NB_FUTURE="$(gen_date  $((365 * 86400)))"            # 1 year from now
NA_FUTURE="$(gen_date  $((2 * 365 * 86400)))"        # 2 years from now

issue_rsa_leaf_dated "expired.example.com" "expired" "$NB_EXPIRED" "$NA_EXPIRED"
issue_rsa_leaf_dated "future.example.com"  "future"  "$NB_FUTURE"  "$NA_FUTURE"

# ---- 6. Encrypted variant of b's key ----------------------------------------

"$OPENSSL" pkcs8 -topk8 -in b.key -passout "pass:${PASS}" -out b.enc.key \
  >/dev/null 2>&1

# ---- 7. Password files ------------------------------------------------------

printf "%s\n" "$PASS" > pwd.txt
printf "%s"   "$PASS" > pwd_notrim.txt

echo "$DIR"
