#!/bin/bash

#This script will copy public key of from the remote server and import it into trusStore.
#Can be used to establish trust against any given server

#Here:
#server URL (e.g google.com)
#Extracted certificate file from the remote server will also be named as {REMOTE_HOST}.cer
REMOTE_HOST=google.com
#port on which server is listening for SSL connections(usually 443, can be 8443 for Tomcat instances)
PORT=443
#name of the trust store which will be created and used to import extracted remote certificate.
KEYSTOREFILE=trustStore
#password to the set for the trust store
KEYSTOREPASS=P@ssw0rd

# get the SSL certificate and store it in a local file
openssl s_client -connect ${REMOTE_HOST}:${PORT} </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ${REMOTE_HOST}.cer

# create a JKS trust store and import certificate from a file into it
keytool -import -noprompt -trustcacerts -alias ${REMOTE_HOST} -file ${REMOTE_HOST}.cer -keystore ${KEYSTOREFILE}.jks -storepass ${KEYSTOREPASS}

# verify we've got it.
keytool -list -v -keystore ${KEYSTOREFILE}.jks -storepass ${KEYSTOREPASS}
