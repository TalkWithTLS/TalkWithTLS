#!/bin/bash

mkdir demoCA
touch demoCA/index.txt

openssl genpkey -algorithm ED25519 -out rootkey.pem
openssl req -config openssl.cnf -key rootkey.pem -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=root" -new -x509 -days 14600 -extensions v3_ca -out rootcert.pem

openssl genpkey -algorithm ED25519 -out serv_key.pem
openssl req -config openssl.cnf -new -key serv_key.pem -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=serv" -out serv.csr.pem
openssl ca -config openssl.cnf -days 14600 -extensions usr_cert -cert rootcert.pem -keyfile rootkey.pem -outdir . -rand_serial -in serv.csr.pem -out serv_cert.pem

openssl x509 -inform PEM -in rootcert.pem -outform DER -out rootcert.der
openssl x509 -inform PEM -in serv_cert.pem -outform DER -out serv_cert.der

rm *.csr.pem
rm demoCA -rf
