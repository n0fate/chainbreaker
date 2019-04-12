#!/bin/bash

for c in exported/certs/* ; do
	echo "=================================="
	echo "Certificate: $c"
	openssl x509 -noout -text -inform DER -in $c | grep Subject:
	for k in exported/keys/* ; do
		if cmp --quiet <(openssl x509 -pubkey -inform DER -in $c -noout) <(openssl pkey -pubout -inform DER -in $k -outform PEM) ; then
			echo "Key: $k"
		fi
	done
done

