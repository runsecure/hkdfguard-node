#!/usr/bin/env bash
#
# Regenerates the TLS test fixtures the package's tests read: a CA, an intermediate, a server
# certificate for vault.test, client identities, and the PKCS#12, JKS and PEM stores built from
# them. Every key here is a throwaway, made for these tests and trusted nowhere else. Needs openssl
# (3.x, with its legacy provider) and keytool (Java 11.0.12 or later) on PATH. Run from this
# directory; under Git Bash on Windows, as
#   MSYS_NO_PATHCONV=1 OPENSSL_MODULES="C:/Program Files/Git/mingw64/lib/ossl-modules" ./generate.sh
set -euo pipefail

readonly DAYS=36500
readonly PASSWORD=store-pass-1
rm -f -- *.pem *.key *.p12 *.jks *.srl *.cnf

ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

cat > ca.cnf <<'CNF'
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
CNF
cat > server.cnf <<'CNF'
subjectAltName = DNS:vault.test
extendedKeyUsage = serverAuth
CNF
cat > client.cnf <<'CNF'
extendedKeyUsage = clientAuth
CNF

ec_key ca.key
openssl req -x509 -new -key ca.key -subj "/CN=HkdfGuard Test CA" -days "${DAYS}" -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
ec_key intermediate.key
openssl req -new -key intermediate.key -subj "/CN=HkdfGuard Test Intermediate" \
    | openssl x509 -req -CA ca.pem -CAkey ca.key -CAcreateserial -days "${DAYS}" -extfile ca.cnf -out intermediate.pem

ec_key server.key
openssl req -new -key server.key -subj "/CN=vault.test" \
    | openssl x509 -req -CA ca.pem -CAkey ca.key -CAcreateserial -days "${DAYS}" -extfile server.cnf -out server.pem

for name in client other; do
    ec_key "${name}.key"
    openssl req -new -key "${name}.key" -subj "/CN=hkdfguard-${name}" \
        | openssl x509 -req -CA intermediate.pem -CAkey intermediate.key -CAcreateserial -days "${DAYS}" -extfile client.cnf -out "${name}.pem"
done
cat intermediate.pem ca.pem > client-chain.pem

# OpenSSL 3's defaults: PBES2 with PBKDF2 and AES-256-CBC, under an HMAC-SHA256 MAC.
openssl pkcs12 -export -inkey client.key -in client.pem -certfile client-chain.pem -name vault-client -passout "pass:${PASSWORD}" -out client.p12
openssl pkcs12 -export -inkey other.key -in other.pem -certfile client-chain.pem -name other -passout "pass:${PASSWORD}" -out other.p12
# PKCS#12's own triple-DES encryption, under an HMAC-SHA1 MAC, as older tools write.
openssl pkcs12 -export -inkey client.key -in client.pem -certfile client-chain.pem -name vault-client -passout "pass:${PASSWORD}" \
    -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 -out client-3des.p12
# OpenSSL's -legacy: RC2-40 for the certificates, which is refused.
openssl pkcs12 -export -legacy -inkey client.key -in client.pem -name vault-client -passout "pass:${PASSWORD}" -out client-rc2.p12
# Certificates only, as `openssl pkcs12 -nokeys` writes a trust store.
openssl pkcs12 -export -nokeys -in ca.pem -passout "pass:${PASSWORD}" -out truststore-openssl.p12

# Java's: two keys in one store, a trust store of trusted certificate entries, and a JKS store.
keytool -importkeystore -srckeystore client.p12 -srcstoretype PKCS12 -srcstorepass "${PASSWORD}" \
    -destkeystore two-keys.p12 -deststoretype PKCS12 -deststorepass "${PASSWORD}" -noprompt
keytool -importkeystore -srckeystore other.p12 -srcstoretype PKCS12 -srcstorepass "${PASSWORD}" \
    -destkeystore two-keys.p12 -deststoretype PKCS12 -deststorepass "${PASSWORD}" -noprompt
keytool -importcert -alias hkdfguard-test-ca -file ca.pem -keystore truststore.p12 -storetype PKCS12 -storepass "${PASSWORD}" -noprompt
keytool -importcert -alias hkdfguard-test-ca -file ca.pem -keystore truststore.jks -storetype JKS -storepass "${PASSWORD}" -noprompt

rm -f -- *.srl *.cnf ca.key intermediate.key other.key other.pem other.p12
