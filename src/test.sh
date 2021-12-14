#!/usr/bin/env bash
echo bashshell

dir=C:\\Users\\ASUS\\Desktop\\CA

mkdir $dir\\private
mkdir $dir\\crl

touch $dir\\index.txt

echo 01>serial

openssl rand -out $dir\\private\\.rand 1000


echo CA

#生成根密钥
openssl genrsa -out $dir\\rootca.key 1024

openssl req -x509  -new -nodes -key $dir\\rootca.key -sha256 -days 3650 -subj  "//C=CN/ST=CQ/L=CQ/O=dorby.com/OU=zlex/CN=server.dorby.com" -out $dir\\rootca.pem


echo server

openssl genrsa -out $dir\\server.key 1024

openssl req -new -key $dir\\server.key -out $dir\\server.csr -subj "//C=CN/ST=CQ/L=CQ/O=dorby.com/OU=zlex/CN=server.dorby.com"

openssl x509 -req -in $dir\\server.csr -CA $dir\\rootca.pem -CAkey $dir\\rootca.key -CAcreateserial -out $dir\\server.pem -days 3650 -sha256
#openssl rsa -in $dir\\server.key -pubout -out $dir\\serverpub.key
#openssl pkcs8 -topk8 -in $dir\\server.key -out $dir\\serverpri.key -nocrypt

echo client

openssl genrsa -out $dir\\client.key 1024

openssl req -new -key $dir\\client.key -out $dir\\client.csr -subj "//C=CN/ST=CQ/L=CQ/O=dorby.com/OU=zlex/CN=server.dorby.com"

openssl x509 -req -in $dir\\client.csr -CA $dir\\rootca.pem -CAkey $dir\\rootca.key -CAcreateserial -out $dir\\client.pem -days 3650 -sha256



#openssl pkcs12 -export -out $dir\\certca.p12 -in $dir\\rootca.pem -inkey $dir\\rootca.key -passout pass:111111

#keytool.exe -importkeystore -srckeystore $dir\\certca.p12 -srcstoretype PKCS12 -srcstorepass 111111 -destkeystore $dir\\certca.jks -deststorepass 111111

#openssl pkcs8 -topk8 -inform PEM -outform DER -in $dir\\rootca.pem -out $dir\\rootca.der -nocrypt

#l rsa -in private_key.pem -pubout -outform DER -out public_key.der