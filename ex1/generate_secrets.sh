#! /bin/bash
set -eu

VAULT="./vault"
BASE_VALID_CHARS='A-Za-z0-9_?!@#$&*()-=+,.<>;:'
FLAG_VALID_CHARS='A-Za-z0-9'

mkdir -p $VAULT

tr -dc $BASE_VALID_CHARS < /dev/urandom | head -c 8 > ${VAULT}/cookie.secret

tr -dc $BASE_VALID_CHARS < /dev/urandom | head -c 16 > ${VAULT}/private_key.secret

tr -dc $BASE_VALID_CHARS < /dev/urandom | head -c 32 > ${VAULT}/hmac.secret

echo -n "SCAD{" > ${VAULT}/flag.secret
tr -dc $FLAG_VALID_CHARS < /dev/urandom | head -c 32 >> ${VAULT}/flag.secret
echo -n "}" >> ${VAULT}/flag.secret