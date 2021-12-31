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
    openssl genrsa -out cslm-nginx-server.key 3072
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
    openssl req -new -out cslm-nginx-server.csr -key cslm-nginx-server.key -config openssl-san.cnf -subj "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=NGINX/CN=cslm_nginx"
    openssl x509 -req -days "$DAYS_EXPIRY" -sha384 -extensions v3_req -CA nginx-ca.crt -CAkey nginx-ca.key -CAcreateserial -in cslm-nginx-server.csr -out cslm-nginx-server.crt

)


mkdir -p /usr/local/share/ca-certificates/nginx
cp "$NGINX_KEYS"/nginx-ca.crt /usr/local/share/ca-certificates/nginx
update-ca-certificates
cp /usr/local/share/ca-certificates/nginx/nginx-ca.crt /etc/ssl/certs/csl-ca-cert.pem

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
       server {
           listen 81;
           listen  433 ssl;
           server_name ci_nginx;
           ssl_certificate /etc/nginx_keys/cslm-nginx-server.crt;
           ssl_certificate_key /etc/nginx_keys/cslm-nginx-server.key;
           root /vagrant/nginx-data;
           add_header Strict-Transport-Security max-age=15768000;
           return 200;

           location /basic_auth {
               auth_basic "Integration Reloaded Test Server2";
               auth_basic_user_file /vagrant/nginx-data/basic_auth/.htpasswd;
        }
    }

}
EOF

rm -rf /vagrant/nginx-data/basic_auth
ln -sf . /vagrant/nginx-data/basic_auth
echo 'testuser:$apr1$2XRIqYkh$S6wARB1GBcV50moqQ/brH0' >/vagrant/nginx-data/basic_auth/.htpasswd  # password is testpass


nginx -s reload


setup_docker_registry() {
    rm -rf certs
    mkdir -p certs

    openssl req \
      -newkey rsa:4096 -nodes -sha256 -keyout certs/domain.key \
      -subj "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=DOCKERREGISTRY/CN=localhost" \
      -x509 -days 365 -out certs/domain.crt

    rm -rf /etc/docker/certs.d/localhost:5000/
    mkdir -p /etc/docker/certs.d/localhost:5000/
    cp certs/domain.crt /etc/docker/certs.d/localhost:5000/ca.crt

    docker stop registry >&/dev/null || true
    docker rm registry >&/dev/null || true

    rm -rf auth
    mkdir -p auth

    sudo -H docker run \
      --entrypoint htpasswd \
      registry.hub.docker.com/library/registry:2.7.0 -Bbn testuser testpass > auth/htpasswd

    sudo -H docker run -d \
      -p 5000:443 \
      --name registry \
      -v "$(pwd)"/auth:/auth \
      -v "$(pwd)"/certs:/certs \
      -e "REGISTRY_AUTH=htpasswd" \
      -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
      -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
      -v "$(pwd)"/certs:/certs \
      -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
      -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
      -e REGISTRY_HTTP_ADDR=0.0.0.0:443 \
      registry.hub.docker.com/library/registry:2.7.0
    
    docker stop registry
}

setup_docker_registry

exit 0
