#!/bin/bash

#This script will copy public key of from the remote server and import it into trusStore.
#Can be used to establish trust against any given server

#Here:
#server URL (e.g google.com)
#Extracted certificate file from the remote server will also be named as {HOST}.cer
HOST=google.com
#port on which server is listening for SSL connections(usually 443, can be 8443 for Tomcat instances)
PORT=443
#name of the trust store which will be created and used to import extracted remote certificate.
KEYSTOREFILE=trustStore
#password to the set for the trust store
KEYSTOREPASS=P@ssw0rd

# get the SSL certificate
openssl s_client -connect ${HOST}:${PORT} </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ${HOST}.cer

# create a truststore and import certificate
keytool -import -noprompt -trustcacerts -alias ${HOST} -file ${HOST}.cer -keystore ${KEYSTOREFILE}.jks -storepass ${KEYSTOREPASS}

# verify we've got it.
keytool -list -v -keystore ${KEYSTOREFILE}.jks -storepass ${KEYSTOREPASS}
