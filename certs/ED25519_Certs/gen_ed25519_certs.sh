#!/bin/bash

openssl genpkey -algorithm ED25519 -out rootkey.pem
openssl req -config openssl.cnf -key rootkey.pem -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=root" -new -x509 -days 14600 -extensions v3_ca -out rootcert.pem

openssl genpkey -algorithm ED25519 -out serv_key.pem
openssl req -config openssl.cnf -new -key serv_key.pem -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=serv" -out serv.csr.pem
openssl x509 -req -days 14600 -in serv.csr.pem -signkey rootkey.pem -out serv_cert.pem

openssl genpkey -algorithm ED25519 -out clnt_key.pem
openssl req -config openssl.cnf -new -key clnt_key.pem -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=clnt" -out clnt.csr.pem
openssl x509 -req -days 14600 -in clnt.csr.pem -signkey rootkey.pem -out clnt_cert.pem

rm *.csr.pem
