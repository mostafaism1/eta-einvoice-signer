#!/bin/bash
openssl genrsa 2048 > ca-key.pem \
&& \
openssl req -new -x509 -nodes \
    -days 365000 \
    -subj '/CN=Egypt Trust Sealing CA' \
    -key ca-key.pem \
    -out ca-cert.pem \
&& \
openssl req -newkey rsa:2048 -nodes \
    -days 365000 \
    -subj '/CN=Test Signer' \
    -keyout signer-key.pem \
    -out signer-req.csr \
&& \
openssl x509 -req \
    -set_serial 01 \
    -days 365000 \
    -in signer-req.csr \
    -out signer-cert.pem \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
&& \
openssl pkcs12 -export \
    -name signer-cert-alias \
    -inkey signer-key.pem \
    -in signer-cert.pem \
    -chain \
    -caname ca-cert-alias \
    -CAfile ca-cert.pem \
    -passout pass:42131536 \
    -out signer-key-store.p12