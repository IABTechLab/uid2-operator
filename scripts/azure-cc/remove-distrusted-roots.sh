#!/bin/sh
# Removes distrusted root CAs from every trust store in the image (OS bundle, JDK cacerts, Python certifi)
# and fails the build if any of them is still present.
set -eu

ROOTS='emSign ECC Root CA - G3|AAA Certificate Services'
OS_ROOT_FILES='emSign_ECC_Root_CA_-_G3 AAA_Certificate_Services'
CERTIFI_BUNDLE=$(/venv/bin/python -c 'import certifi; print(certifi.where())')

for f in $OS_ROOT_FILES; do
    sed -i "s|^mozilla/${f}\.crt\$|!mozilla/${f}.crt|" /etc/ca-certificates.conf
done
update-ca-certificates

keytool -list -cacerts -storepass changeit -v \
    | awk -v roots="^Owner: CN=(${ROOTS})," '/^Alias name: /{alias=substr($0, 13)} $0 ~ roots {print alias}' \
    | while IFS= read -r alias; do
        keytool -delete -cacerts -storepass changeit -alias "$alias"
    done

/venv/bin/python - "$CERTIFI_BUNDLE" "$ROOTS" <<'EOF'
import re, sys
path, roots = sys.argv[1], sys.argv[2]
blocks = open(path).read().split('\n\n')
kept = [b for b in blocks if not re.search(rf'^# Subject: CN=({roots})( O=|$)', b, re.M)]
open(path, 'w').write('\n\n'.join(kept))
EOF

found=$( \
    { openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt | openssl pkcs7 -print_certs -noout | grep -E "CN ?= ?(${ROOTS})\$"; \
      keytool -list -cacerts -storepass changeit -v | grep -E "^Owner: CN=(${ROOTS}),"; \
      grep -E "^# Subject: CN=(${ROOTS})( O=|\$)" "$CERTIFI_BUNDLE"; } || true)
if [ -n "$found" ]; then
    echo "Distrusted root CAs still present:" >&2
    echo "$found" >&2
    exit 1
fi
