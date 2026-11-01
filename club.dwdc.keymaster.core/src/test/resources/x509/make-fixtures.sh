#!/bin/sh
# Regenerates the X.509 fixtures for X509CertCheckTest. Run by hand; the build
# never runs it. Writes the certificate PEMs next to this script.
#
# Every private key (both throwaway CAs and the "different key") lives only in
# a temporary directory that is deleted on exit, so no private key is ever
# written to the repository. Alice's private key is never needed: certificates
# are issued over her public key with -force_pubkey.
#
# Needs OpenSSL >= 3.4 (-not_before / -not_after on `openssl x509 -new`).
set -eu

OUT=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/x509-fixtures.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# Alice's TLS client public key: the vault's P-256 key at
# m/44'/1240'/1955269225'/196866'/0' (test mnemonic "abandon x11 about").
# This SPKI is the fixed P-256 prefix
#   3059301306072a8648ce3d020106082a8648ce3d030107034200
# followed by the 37.1.1 point 04b99b60...a81a2a81.
# X509CertCheckTest asserts the vault still derives exactly this point.
cat > "$WORK/alice.pub.pem" <<'EOF'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuZtg1QH4xEEIOXefvqGZ2HuD3Wdf
+6UyI1Ka39DwWsg8GZrdpLe3qq1Qr9PtSyMDYebOVup4eQcHy32EqBoqgQ==
-----END PUBLIC KEY-----
EOF

p256key() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
}

# The test CA (its certificate is committed, its key is not) and a second CA
# that stands in for "some CA nobody configured".
p256key "$WORK/ca.key"
openssl req -x509 -new -key "$WORK/ca.key" -subj "/CN=KeyMaster test CA" \
    -not_before 20260101000000Z -not_after 21260101000000Z -out "$OUT/test-ca.pem"
p256key "$WORK/other-ca.key"
openssl req -x509 -new -key "$WORK/other-ca.key" -subj "/CN=Unknown test CA" \
    -not_before 20260101000000Z -not_after 21260101000000Z -out "$WORK/other-ca.pem"

# A key that is not Alice's.
p256key "$WORK/other.key"
openssl pkey -in "$WORK/other.key" -pubout -out "$WORK/other.pub.pem"

# issue <file> <public key> <ca cert> <ca key> <not before> <not after> [EKU]
issue() {
    file=$1 pub=$2 ca=$3 cakey=$4 from=$5 until=$6 eku=${7:-}
    {
        echo "basicConstraints = critical, CA:FALSE"
        echo "keyUsage = critical, digitalSignature"
        if [ -n "$eku" ]; then echo "extendedKeyUsage = $eku"; fi
    } > "$WORK/ext.cnf"
    openssl x509 -new -force_pubkey "$pub" -subj "/CN=alice@atlanta.com" \
        -CA "$ca" -CAkey "$cakey" -not_before "$from" -not_after "$until" \
        -extfile "$WORK/ext.cnf" -out "$OUT/$file"
}

VALID="20260101000000Z 21260101000000Z"
CA="$OUT/test-ca.pem $WORK/ca.key"
ALICE="$WORK/alice.pub.pem"

# shellcheck disable=SC2086  # $CA and $VALID are deliberately split
issue tls-client-ok.pem    "$ALICE" $CA $VALID clientAuth
issue client-and-email.pem "$ALICE" $CA $VALID "clientAuth, emailProtection"
issue server-auth.pem      "$ALICE" $CA $VALID serverAuth
issue any-eku.pem          "$ALICE" $CA $VALID anyExtendedKeyUsage
issue no-eku.pem           "$ALICE" $CA $VALID
issue expired.pem          "$ALICE" $CA 20200101000000Z 20210101000000Z clientAuth
issue different-key.pem    "$WORK/other.pub.pem" $CA $VALID clientAuth
issue unknown-ca.pem       "$ALICE" "$WORK/other-ca.pem" "$WORK/other-ca.key" $VALID clientAuth

echo "fixtures written to $OUT"
