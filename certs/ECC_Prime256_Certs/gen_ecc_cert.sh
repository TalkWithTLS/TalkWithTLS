#!/bin/bash

openssl ecparam -genkey -name prime256v1 -conv_form uncompressed -outform PEM -out ec.pem
openssl req -newkey ec:ec.pem -passout pass:123456 -sha256 -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=root/emailaddress=root@abc.com" -keyout rootkey.pem -out rootreq.pem -config openssl.cnf
openssl x509 -req -in rootreq.pem -passin pass:123456 -sha256 -extfile openssl.cnf -days 14600 -extensions v3_ca -signkey rootkey.pem -out rootcert.pem 

openssl ecparam -genkey -name prime256v1 -conv_form uncompressed -outform PEM -out ec.pem
openssl req -newkey ec:ec.pem -passout pass:123456 -sha256 -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=mptun_server/emailaddress=mptunsp@abc.com" -keyout serv_key.pem -out serv_req.pem -config openssl.cnf
openssl x509 -req -in serv_req.pem -passin pass:123456 -sha256 -extfile openssl.cnf -days 14600 -extensions usr_cert -CA rootcert.pem -CAkey rootkey.pem -CAcreateserial -out serv_cert.pem

openssl ecparam -genkey -name prime256v1 -conv_form uncompressed -outform PEM -out ec.pem
openssl req -newkey ec:ec.pem -passout pass:123456 -sha256 -subj "/C=IN/ST=Kar/L=En/O=HTIPL/OU=VPP/CN=sample_client/emailaddress=mptunsp@abc.com" -keyout client_key.pem -out client_req.pem -config openssl.cnf
openssl x509 -req -in client_req.pem -passin pass:123456 -sha256 -extfile openssl.cnf -days 14600 -extensions usr_cert -CA rootcert.pem -CAkey rootkey.pem -CAcreateserial -out client_cert.pem

openssl x509 -inform PEM -in rootcert.pem -outform DER -out rootcert.der
openssl ec -inform PEM -passin pass:123456 -in rootkey.pem -outform DER -out rootkey.der
openssl x509 -inform PEM -in serv_cert.pem -outform DER -out serv_cert.der
openssl ec -inform PEM -passin pass:123456 -in serv_key.pem -outform DER -out serv_key.der
openssl x509 -inform PEM -in client_cert.pem -outform DER -out client_cert.der
openssl ec -inform PEM -passin pass:123456 -in client_key.pem -outform DER -out client_key.der

# generate unencrypted PEM key file
openssl ec -inform PEM -passin pass:123456 -in rootkey.pem -outform PEM -out rootkey_unencrypted.pem
openssl ec -inform PEM -passin pass:123456 -in serv_key.pem -outform PEM -out serv_key_unencrypted.pem
openssl ec -inform PEM -passin pass:123456 -in client_key.pem -outform PEM -out client_key_unencrypted.pem

rm ec.pem rootreq.pem serv_req.pem client_req.pem
