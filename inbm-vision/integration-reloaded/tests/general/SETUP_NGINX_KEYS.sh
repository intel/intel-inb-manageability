#!/bin/bash
set -euxo pipefail

# This script sets up nginx private test keys for integration testing

NGINX_KEYS=/etc/nginx_keys/
DAYS_EXPIRY=365

# Ensure keys are provisioned
mkdir -p "$NGINX_KEYS"

(   cd "$NGINX_KEYS"
    openssl genrsa -out nginx-ca.key 3072
    openssl req -new -key nginx-ca.key -subj "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=NGINX/CN=nginx-ca.example.com" -out nginx-ca.csr
    openssl x509 -req -days "$DAYS_EXPIRY" -sha384 -extensions v3-ca -signkey nginx-ca.key -in nginx-ca.csr -out nginx-ca.crt
    openssl genrsa -out nginx-server.key 3072
    cat >openssl-san.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ci_nginx

[req_distinguished_name]
EOF
    openssl req -new -out nginx-server.csr -key nginx-server.key -config openssl-san.cnf -subj "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=NGINX/CN=ci_nginx"
    openssl x509 -req -days "$DAYS_EXPIRY" -sha384 -extensions v3_req -CA nginx-ca.crt -CAkey nginx-ca.key -CAcreateserial -in nginx-server.csr -out nginx-server.crt
)


mkdir -p /usr/local/share/ca-certificates/nginx
cp "$NGINX_KEYS"/nginx-ca.crt /usr/local/share/ca-certificates/nginx
update-ca-certificates

cat >/etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
        worker_connections 768;
        # multi_accept on;
}

http {
        server {
           listen 80;
           listen  443 ssl;
           server_name ci_nginx;
           ssl_certificate /etc/nginx_keys/nginx-server.crt;
           ssl_certificate_key /etc/nginx_keys/nginx-server.key;
           root /vagrant/nginx-data;

           location /basic_auth {
               auth_basic "Integration Reloaded Test Server";
               auth_basic_user_file /vagrant/nginx-data/basic_auth/.htpasswd;
        }
    }
}
EOF

rm -rf /vagrant/nginx-data/basic_auth
ln -sf . /vagrant/nginx-data/basic_auth
echo 'testuser:$apr1$2XRIqYkh$S6wARB1GBcV50moqQ/brH0' >/vagrant/nginx-data/basic_auth/.htpasswd  # password is testpass


nginx -s reload

echo Test that server is behaving as we expect.

exit 0
