#!/bin/bash

#Root CA cert and private key file generation
openssl ecparam -genkey -name prime256v1 -conv_form uncompressed -outform PEM -out ec.pem
openssl req -newkey ec:ec.pem -passout pass:123456 -sha256 -subj "/C=IN/ST=Kar/L=En/O=OpenSource/OU=OS/CN=root/emailaddress=root@abc.com" -keyout rootkey.pem -out rootreq.pem -config openssl.cnf
openssl x509 -req -in rootreq.pem -passin pass:123456 -sha256 -extfile openssl.cnf -days 14600 -extensions v3_ca -signkey rootkey.pem -out rootcert.pem 

openssl ecparam -genkey -name prime256v1 -conv_form uncompressed -outform PEM -out ec.pem
openssl req -newkey ec:ec.pem -passout pass:123456 -sha256 -subj "/C=IN/ST=Kar/L=En/O=OpenSource/OU=OS/CN=interca/emailaddress=interca@abc.com" -keyout inter_ca_key.pem -out inter_ca_req.pem -config openssl.cnf
openssl x509 -req -in inter_ca_req.pem -passin pass:123456 -sha256 -extfile openssl.cnf -days 14600 -extensions v3_ca -CA rootcert.pem -CAkey rootkey.pem -CAcreateserial -out inter_ca_cert.pem

openssl ecparam -genkey -name prime256v1 -conv_form uncompressed -outform PEM -out ec.pem
openssl req -newkey ec:ec.pem -passout pass:123456 -sha256 -subj "/C=IN/ST=Kar/L=En/O=OpenSource/OU=OS/CN=web_server/emailaddress=web_server@abc.com" -keyout server_key.pem -out server_req.pem -config openssl.cnf
openssl x509 -req -in server_req.pem -passin pass:123456 -sha256 -extfile openssl.cnf -days 14600 -extensions usr_cert -CA inter_ca_cert.pem -CAkey inter_ca_key.pem -CAcreateserial -out server_cert.pem

openssl x509 -inform PEM -in rootcert.pem -outform DER -out rootcert.der
openssl ec -inform PEM -passin pass:123456 -in rootkey.pem -outform DER -out rootkey.der
openssl x509 -inform PEM -in inter_ca_cert.pem -outform DER -out inter_ca_cert.der
openssl ec -inform PEM -passin pass:123456 -in inter_ca_key.pem -outform DER -out inter_ca_key.der
openssl x509 -inform PEM -in server_cert.pem -outform DER -out server_cert.der
openssl ec -inform PEM -passin pass:123456 -in server_key.pem -outform DER -out server_key.der

rm ec.pem rootreq.pem inter_ca_req.pem server_req.pem *.srl
