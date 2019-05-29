#!/bin/bash -e -u -x

BASE_SUBJ="C=XX/ST=state/L=city/O=company/U=section/emailAddress=example.com"

# Setup Demo CA

rm -rf ./demoCA
mkdir -p demoCA/newcerts
touch demoCA/index.txt
touch demoCA/index.txt.attr
echo "01" > demoCA/serial

openssl genrsa -out root_CA.key 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key root_CA.key\
            -out root_CA.crt\
            -config config.cnf\
            -subj "/CN=Demo CA/${BASE_SUBJ}"\

# Setup End User Certificate

openssl genrsa -out local_ocsp_urls.key 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key local_ocsp_urls.key\
            -out local_ocsp_urls.crt\
            -config config.cnf\
            -subj "/CN=Local OCSP URLs/${BASE_SUBJ}"

openssl x509 -x509toreq\
             -in local_ocsp_urls.crt\
             -out local_ocsp_urls.csr\
             -signkey local_ocsp_urls.key\

openssl ca -batch\
           -startdate 150813080000Z\
           -enddate 250813090000Z\
           -keyfile root_CA.key\
           -cert root_CA.crt\
           -policy policy_anything\
           -config config.cnf\
           -extensions local_ocsp\
           -notext\
           -out local_ocsp_urls.crt\
           -infiles local_ocsp_urls.csr

rm local_ocsp_urls.csr

# Setup End User Certificate with no OCSP URLs

openssl genrsa -out no_ocsp_urls.key 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key no_ocsp_urls.key\
            -out no_ocsp_urls.crt\
            -config config.cnf\
            -subj "/CN=No OCSP URLs/${BASE_SUBJ}"\

openssl x509 -x509toreq\
             -in no_ocsp_urls.crt\
             -out no_ocsp_urls.csr\
             -signkey no_ocsp_urls.key

openssl ca -batch\
           -startdate 150813080000Z\
           -enddate 250813090000Z\
           -keyfile root_CA.key\
           -cert root_CA.crt\
           -policy policy_anything\
           -config config.cnf\
           -notext\
           -out no_ocsp_urls.crt\
           -infiles no_ocsp_urls.csr

rm no_ocsp_urls.csr

# Setup End User Certificate with bad OCSP URLs

openssl genrsa -out bad_ocsp_urls.key 1024

openssl req -new\
            -x509\
            -batch\
            -days 3650\
            -key bad_ocsp_urls.key\
            -out bad_ocsp_urls.crt\
            -config config.cnf\
            -subj "/CN=Bad OCSP URLs/${BASE_SUBJ}"

openssl x509 -x509toreq\
             -in bad_ocsp_urls.crt\
             -out bad_ocsp_urls.csr\
             -signkey bad_ocsp_urls.key

openssl ca -batch\
           -startdate 150813080000Z\
           -enddate 250813090000Z\
           -keyfile root_CA.key\
           -cert root_CA.crt\
           -policy policy_anything\
           -config config.cnf\
           -extensions bad_ocsp\
           -notext\
           -out bad_ocsp_urls.crt\
           -infiles bad_ocsp_urls.csr

rm bad_ocsp_urls.csr

# Setup OCSP Server

openssl req -new\
            -nodes\
            -out ocsp_signing.csr\
            -keyout ocsp_signing.key\
            -config config.cnf\
            -subj "/CN=OCSP Server/${BASE_SUBJ}"

openssl ca -batch\
           -keyfile root_CA.key\
           -cert root_CA.crt\
           -in ocsp_signing.csr\
           -out ocsp_signing.crt\
           -config config.cnf\
           -extensions v3_OCSP

rm ocsp_signing.csr

# Convert certs to DER format for easier loading in tests

openssl x509 -in local_ocsp_urls.crt\
             -outform DER\
             -out local_ocsp_urls.der

openssl x509 -in no_ocsp_urls.crt\
             -outform DER\
             -out no_ocsp_urls.der

openssl x509 -in bad_ocsp_urls.crt\
             -outform DER\
             -out bad_ocsp_urls.der

openssl x509 -in root_CA.crt\
             -outform DER\
             -out root_CA.der
