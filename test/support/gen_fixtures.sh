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
# Requirements:
#   - openssl 3.0+
#   - one of:
#       * faketime (libfaketime), preferred and recommended; or
#       * openssl 3.2+ (which provides x509 -not_before/-not_after)
#     ...for minting the date-shifted "expired" and "future" leaves.
#
#   On macOS:    brew install libfaketime
#   On Ubuntu:   sudo apt-get install -y faketime
#
# Files produced (in TARGET_DIR):
#   ca.pem            self-signed root CA cert
#   ca.key            root CA private key (RSA, unencrypted)
#   a.pem  / a.key    RSA leaf for "a.example.com" (unencrypted)
#   b.pem  / b.key    RSA leaf for "b.example.com" (unencrypted)
#   b.enc.key         same key as b.key, encrypted with passphrase "secret"
#   b.enc.legacy.key  same key encrypted as traditional PEM (PKCS#1) with DES-CBC
#   wild.pem / wild.key   RSA leaf SAN=*.wild.example.com
#   ec.pem  / ec.key      ECDSA leaf for "ec.example.com"
#   ed.pem  / ed.key      Ed25519 leaf for "ed.example.com"  (best-effort)
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
  >/dev/null

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
    >/dev/null
  "$OPENSSL" x509 -req -in "${stem}.csr" \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out "${stem}.pem" -days 365 \
    -copy_extensions copy \
    >/dev/null
  rm -f "${stem}.csr"
}

# Mint a leaf with a custom not-before / not-after.
#
# $1 cn      Subject CN + dNSName SAN
# $2 stem    output filename stem
# $3 nb_offset_seconds  notBefore relative to now (negative = past)
# $4 na_offset_seconds  notAfter  relative to now (negative = past)
#
# Prefers faketime (rewinds the wall clock and uses -days N) for portability
# across openssl versions; falls back to openssl 3.2+ -not_before/-not_after.
issue_rsa_leaf_dated() {
  local cn="$1" stem="$2" nb_off="$3" na_off="$4"

  "$OPENSSL" req -new -newkey rsa:2048 -nodes \
    -keyout "${stem}.key" -out "${stem}.csr" \
    -subj "/CN=${cn}" \
    -addext "subjectAltName=DNS:${cn}" \
    >/dev/null

  local days=$(( (na_off - nb_off + 86399) / 86400 ))
  if (( days < 1 )); then days=1; fi

  if command -v faketime >/dev/null 2>&1; then
    local now_epoch nb_epoch
    now_epoch="$(date -u +%s)"
    nb_epoch=$(( now_epoch + nb_off ))
    faketime "@${nb_epoch}" "$OPENSSL" x509 -req -in "${stem}.csr" \
      -CA ca.pem -CAkey ca.key -CAcreateserial \
      -out "${stem}.pem" -days "${days}" \
      -copy_extensions copy \
      >/dev/null
  elif "$OPENSSL" x509 -help 2>&1 | grep -q -- '-not_before'; then
    local nb na
    nb="$(gen_date "$nb_off")"
    na="$(gen_date "$na_off")"
    "$OPENSSL" x509 -req -in "${stem}.csr" \
      -CA ca.pem -CAkey ca.key -CAcreateserial \
      -out "${stem}.pem" \
      -not_before "$nb" -not_after "$na" \
      -copy_extensions copy \
      >/dev/null
  else
    echo "ERROR: need 'faketime' or openssl 3.2+ to mint dated certs" >&2
    "$OPENSSL" version >&2
    exit 1
  fi

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
  >/dev/null
"$OPENSSL" x509 -req -in ec.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out ec.pem -days 365 \
  -copy_extensions copy \
  >/dev/null
rm -f ec.csr

# ---- 4. Wildcard SAN --------------------------------------------------------

"$OPENSSL" req -new -newkey rsa:2048 -nodes \
  -keyout wild.key -out wild.csr \
  -subj "/CN=wild.example.com" \
  -addext "subjectAltName=DNS:*.wild.example.com" \
  >/dev/null
"$OPENSSL" x509 -req -in wild.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out wild.pem -days 365 \
  -copy_extensions copy \
  >/dev/null
rm -f wild.csr

# ---- 5. Expired and future leaves -------------------------------------------

# Portable date-from-offset for the openssl 3.2+ fallback path.
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

issue_rsa_leaf_dated "expired.example.com" "expired" \
  "$((-2 * 365 * 86400))" "-86400"

issue_rsa_leaf_dated "future.example.com" "future" \
  "$((365 * 86400))" "$((2 * 365 * 86400))"

# ---- 6. Encrypted variant of b's key ----------------------------------------

"$OPENSSL" pkcs8 -topk8 -in b.key -passout "pass:${PASS}" -out b.enc.key \
  >/dev/null

# Traditional (PKCS#1) encrypted PEM, so we exercise the non-PKCS#8
# encrypted-key code path in :public_key.pem_entry_decode/2.
"$OPENSSL" rsa -in b.key -aes256 -passout "pass:${PASS}" -out b.enc.legacy.key \
  >/dev/null 2>&1 || cp b.enc.key b.enc.legacy.key

# ---- 6.5 Ed25519 leaf -------------------------------------------------------
#
# Best-effort: not all environments (some BoringSSL builds, ancient
# openssl) can mint Ed25519 leaves. If anything fails we fall back to
# copying the ECDSA pair so the file paths always exist (tests that care
# about Ed25519 specifically tag :eddsa and skip when unsupported).

if "$OPENSSL" genpkey -algorithm Ed25519 -out ed.key 2>/dev/null; then
  "$OPENSSL" req -new -key ed.key -out ed.csr \
    -subj "/CN=ed.example.com" \
    -addext "subjectAltName=DNS:ed.example.com" \
    >/dev/null 2>&1 && \
    "$OPENSSL" x509 -req -in ed.csr \
      -CA ca.pem -CAkey ca.key -CAcreateserial \
      -out ed.pem -days 365 \
      -copy_extensions copy \
      >/dev/null 2>&1 || {
        cp ec.key ed.key
        cp ec.pem ed.pem
      }
  rm -f ed.csr
else
  cp ec.key ed.key
  cp ec.pem ed.pem
fi

# ---- 6.6 Cert with multi-attribute subject and no SAN ----------------------
#
# Exercises the rdnSequence iteration and the subject_cn fallback path
# in Snippy.Decoder when an RDN attribute is *not* CN, plus the
# `:asn1_NOVALUE` san_dns_names branch when no SAN extension is present.

"$OPENSSL" req -new -newkey rsa:2048 -nodes \
  -keyout nosan.key -out nosan.csr \
  -subj "/C=US/ST=CA/L=SF/O=SnippyTestOrg/CN=nosan.example.com" \
  >/dev/null
"$OPENSSL" x509 -req -in nosan.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out nosan.pem -days 365 \
  >/dev/null
rm -f nosan.csr

# ---- 7. Password files ------------------------------------------------------

printf "%s\n" "$PASS" > pwd.txt
printf "%s"   "$PASS" > pwd_notrim.txt

echo "$DIR"
