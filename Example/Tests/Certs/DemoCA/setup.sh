#!/bin/bash

set -o errexit
set -o nounset
set -o xtrace

BASE_DIR=$PWD

BASE_SUBJ="C=XX/ST=state/L=city/O=company"

# Setup Demo CA

rm -rf ./CA

ROOT_CA_CNF=$PWD/root-ca.cnf
INTERMEDIATE_CA_CNF=$PWD/intermediate-ca.cnf

ROOT_CA_CERTS_DIR=$PWD/CA/root
INTERMEDIATE_CA_CERTS_DIR=$PWD/CA/intermediate/enduser-certs

mkdir -p "$ROOT_CA_CERTS_DIR"

ROOT_CA_KEY=$ROOT_CA_CERTS_DIR/root_CA.key
ROOT_CA_CRT=$ROOT_CA_CERTS_DIR/root_CA.crt

INTERMEDIATE_CA_KEY=$ROOT_CA_CERTS_DIR/intermediate_CA.key
INTERMEDIATE_CA_CRT=$ROOT_CA_CERTS_DIR/intermediate_CA.crt
INTERMEDIATE_CA_CSR=$ROOT_CA_CERTS_DIR/intermediate_CA.csr

cd "$ROOT_CA_CERTS_DIR"

openssl genrsa -out "$ROOT_CA_KEY" 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key "$ROOT_CA_KEY"\
            -out "$ROOT_CA_CRT"\
            -config "$ROOT_CA_CNF"\
            -subj "/CN=Root CA/${BASE_SUBJ}"

openssl x509 -in "$ROOT_CA_CRT"\
             -outform DER\
             -out ./root_CA.der

openssl x509 -in "$ROOT_CA_CRT"\
             -outform PEM\
             -out ./root_CA.pem

## Configure

touch certindex
echo 1000 > certserial
echo 1000 > crlnumber

# Setup Intermediate Certificate

openssl genrsa -out "$INTERMEDIATE_CA_KEY" 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key "$INTERMEDIATE_CA_KEY"\
            -out "$INTERMEDIATE_CA_CRT"\
            -config "$ROOT_CA_CNF"\
            -subj "/CN=Intermediate CA/${BASE_SUBJ}"

openssl x509 -x509toreq\
             -in "$INTERMEDIATE_CA_CRT"\
             -out "$INTERMEDIATE_CA_CSR"\
             -signkey "$INTERMEDIATE_CA_KEY"\

openssl ca -batch\
           -config "$ROOT_CA_CNF"\
           -notext\
           -in "$INTERMEDIATE_CA_CSR"\
           -out "$INTERMEDIATE_CA_CRT"

rm "$INTERMEDIATE_CA_CSR"

openssl x509 -in "$INTERMEDIATE_CA_CRT"\
             -outform DER\
             -out ./intermediate_CA.der

openssl x509 -in "$INTERMEDIATE_CA_CRT"\
             -outform PEM\
             -out ./intermediate_CA.pem

## Configure

mkdir -p "$INTERMEDIATE_CA_CERTS_DIR"

cd "$INTERMEDIATE_CA_CERTS_DIR"

touch certindex
echo 1000 > certserial
echo 1000 > crlnumber

# Setup End User Certificates

## Setup End User Certificate with local OCSP URLs

openssl genrsa -out local_ocsp_urls.key 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key local_ocsp_urls.key\
            -out local_ocsp_urls.crt\
            -config "$INTERMEDIATE_CA_CNF"\
            -subj "/CN=localhost/${BASE_SUBJ}"

openssl x509 -x509toreq\
             -in local_ocsp_urls.crt\
             -out local_ocsp_urls.csr\
             -signkey local_ocsp_urls.key\

OCSP_SECTION="local_ocsp" \
openssl ca -batch\
           -startdate 150813080000Z\
           -enddate 250813090000Z\
           -keyfile "$INTERMEDIATE_CA_KEY"\
           -cert "$INTERMEDIATE_CA_CRT"\
           -config "$INTERMEDIATE_CA_CNF"\
           -notext\
           -out local_ocsp_urls.crt\
           -infiles local_ocsp_urls.csr

rm local_ocsp_urls.csr

openssl x509 -in ./local_ocsp_urls.crt\
             -outform DER\
             -out ./local_ocsp_urls.der

openssl x509 -in ./local_ocsp_urls.crt\
             -outform PEM\
             -out ./local_ocsp_urls.pem

# Setup End User Certificate with no OCSP URLs

openssl genrsa -out no_ocsp_urls.key 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key no_ocsp_urls.key\
            -out no_ocsp_urls.crt\
            -config "$INTERMEDIATE_CA_CNF"\
            -subj "/CN=No OCSP URLs/${BASE_SUBJ}"

openssl x509 -x509toreq\
             -in no_ocsp_urls.crt\
             -out no_ocsp_urls.csr\
             -signkey no_ocsp_urls.key

openssl ca -batch\
           -startdate 150813080000Z\
           -enddate 250813090000Z\
           -keyfile "$INTERMEDIATE_CA_KEY"\
           -cert "$INTERMEDIATE_CA_CRT"\
           -config "$INTERMEDIATE_CA_CNF"\
           -extensions no_ocsp_urls\
           -notext\
           -out no_ocsp_urls.crt\
           -infiles no_ocsp_urls.csr

rm no_ocsp_urls.csr

openssl x509 -in ./no_ocsp_urls.crt\
             -outform DER\
             -out ./no_ocsp_urls.der

# Setup End User Certificate with bad OCSP URLs

openssl genrsa -out bad_ocsp_urls.key 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key bad_ocsp_urls.key\
            -out bad_ocsp_urls.crt\
            -config "$INTERMEDIATE_CA_CNF"\
            -subj "/CN=Bad OCSP URLs/${BASE_SUBJ}"\

openssl x509 -x509toreq\
             -in bad_ocsp_urls.crt\
             -out bad_ocsp_urls.csr\
             -signkey bad_ocsp_urls.key

OCSP_SECTION="bad_ocsp" \
openssl ca -batch\
           -startdate 150813080000Z\
           -enddate 250813090000Z\
           -keyfile "$INTERMEDIATE_CA_KEY"\
           -cert "$INTERMEDIATE_CA_CRT"\
           -config "$INTERMEDIATE_CA_CNF"\
           -notext\
           -out bad_ocsp_urls.crt\
           -infiles bad_ocsp_urls.csr

rm bad_ocsp_urls.csr

openssl x509 -in ./bad_ocsp_urls.crt\
             -outform DER\
             -out ./bad_ocsp_urls.der

# Setup Root OCSP Server

cd "$ROOT_CA_CERTS_DIR"

openssl req -new\
            -nodes\
            -out ocsp_signing.csr\
            -keyout ocsp_signing.key\
            -config "$ROOT_CA_CNF"\
            -subj "/CN=Root CA OCSP Server/${BASE_SUBJ}"

openssl ca -batch\
           -keyfile "$ROOT_CA_KEY"\
           -cert root_CA.crt\
           -in ocsp_signing.csr\
           -out ocsp_signing.crt\
           -config "$ROOT_CA_CNF"\
           -extensions v3_ocsp

rm ocsp_signing.csr

# Setup Intermediate OCSP Server

cd "$INTERMEDIATE_CA_CERTS_DIR"

openssl req -new\
            -nodes\
            -out ocsp_signing.csr\
            -keyout ocsp_signing.key\
            -config "$INTERMEDIATE_CA_CNF"\
            -subj "/CN=Intermediate CA OCSP Server/${BASE_SUBJ}"

openssl ca -batch\
           -keyfile "$INTERMEDIATE_CA_KEY"\
           -cert "$INTERMEDIATE_CA_CRT"\
           -in ocsp_signing.csr\
           -out ocsp_signing.crt\
           -config "$INTERMEDIATE_CA_CNF"\
           -extensions v3_ocsp

rm ocsp_signing.csr

# Setup certificate chain for server

cd "$BASE_DIR"/CA
touch cert_chain.pem
cat "$INTERMEDIATE_CA_CERTS_DIR"/local_ocsp_urls.pem >> cert_chain.pem
cat "$ROOT_CA_CERTS_DIR"/intermediate_CA.pem >> cert_chain.pem
