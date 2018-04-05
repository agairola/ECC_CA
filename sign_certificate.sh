#!/bin/bash
# Author - gaiadesh@amazon.com

OPENSSL=/usr/bin/openssl
 
if [ ! $# -ge 2 ]; then
    echo " "
    echo " USAGE: ${0} <hostname> <key len> [hash len] {-S or -C}"
    echo "        key length:  256, 384"
    echo "        hash length: 256, 384, 512"
    echo "        -S to flag server-auth EKU in the certificate"
    echo "        -C to flag client-auth EKU in the certificate"
    echo " "
    exit 1
fi
 
#Interesting Curves:
#openssl ecparam -list_curves
#  prime256v1: P256
#  secp384r1 : P384
 
if [ "${2}" == "256" ]; then
    curve=prime256v1
elif [ "${2}" == "384" ]; then
    curve=secp384r1
else
    echo " "
    echo "    ERROR: Invalid EC curve length: (${2})."
    echo " "
    exit 1
fi
keylen=${2}
echo " "
echo "  Using EC curve ${curve}."
 
if [ "X${3}" == "X"  -a  "${2}" == "256"  -o  "${2}" == "384" ]; then
    hash=sha${2}
elif [ "X${3}" == "X"  -a  "${2}" == "512"]; then
    echo " "
    echo "    ERROR: Invalid hash length: (${3}) assumed from curve len."
    echo "           Please specify 256, 384, or 512"
    echo " "
    exit 1
elif [ "${3}" == "256" ]; then
    hash=sha${3}
elif [ "${3}" == "384" ]; then
    hash=sha${3}
elif [ "${3}" == "512" ]; then
    hash=sha${3}
else
    echo " "
    echo "    ERROR: Invalid hash length: (sha${3})."
    echo " "
    exit 1
fi
echo "  Signing with ${hash}."
echo " "
 
 
 
cacert=cacert.pem
cakey=private/cakey.pem
 
serverpass=aws12345
clientpass=aws12345
 
hostname=${1}
privkey=keys/${hostname}-key.pem
encrprivkey=keys/${hostname}-keyenc.pem
reqfile=csr/${hostname}-ec${keylen}.csr
certfile=certs/${hostname}-ec${keylen}-crt.pem
p12file=${hostname}-ec${keylen}-crt.p12
fqdn=${1}.AWSLABS.com
 
echo "Generating client private Key..."
$OPENSSL ecparam  -out ${privkey} -name ${curve} -genkey
RETVAL=$?
if [ $RETVAL -ne 0 ]; then
    echo "*** Failed ($?)... exiting."
    exit 1
fi
 
echo " "
echo "Encrypting the private key..."
$OPENSSL ec -in ${privkey} -des3 -out ${encrprivkey} -passout pass:${clientpass}
RETVAL=$?
if [ $RETVAL -ne 0 ]; then
    echo "*** Failed... exiting."
    exit 1
fi
 
echo " "
echo "Generating the client certificate request..."
 
SUBJ="/C=AU/ST=NSW/L=SYD/O=AWSLABS/OU=Support/CN=${fqdn}"
$OPENSSL req -new -sha256 -key ${encrprivkey} \
    -out ${reqfile} -passin pass:${clientpass} -subj "${SUBJ}" -batch

#
# View Req with
# openssl req -noout -text -in file.csr
#
RETVAL=$?
if [ $RETVAL -ne 0 ]; then
    echo "*** Failed... exiting."
    exit 1
fi
 
echo " "
echo "Signing/Issuing the client certificate..."
if [ ${4} = "-S" ]; then
    echo "Certificate will have Server-Auth EKU flagged"
    $OPENSSL ca -config config -extensions server_cert -in ${reqfile} -keyfile ${cakey} -cert ${cacert} \
    -keyform PEM -md ${hash} -out ${certfile} -batch -passin pass:${serverpass}
elif [ ${4} = "-C" ]; then
    echo "Certificate will have Client-Auth EKU flagged"
    $OPENSSL ca -config config -extensions client_cert -in ${reqfile} -keyfile ${cakey} -cert ${cacert} \
    -keyform PEM -md ${hash} -out ${certfile} -batch -passin pass:${serverpass}
else
    echo "Certificate will not have Client or Server Auth EKU flagged"
    $OPENSSL ca -config config -in ${reqfile} -keyfile ${cakey} -cert ${cacert} \
    -keyform PEM -md ${hash} -out ${certfile} -batch -passin pass:${serverpass}
fi
echo " "

RETVAL=$?
if [ $RETVAL -ne 0 ]; then
    echo "*** Failed... exiting."
    exit 1
fi
 
echo " "
echo "Combining certs and keys in to a pkcs12 file..."
$OPENSSL pkcs12 -export -in ${certfile} -inkey ${encrprivkey} -certfile ${cacert} -out ${p12file} \
                -passin pass:${clientpass} -passout pass:${clientpass}
echo " "
RETVAL=$?
if [ $RETVAL -ne 0 ]; then
    echo "*** Failed... exiting."
    exit 1
fi
 
 
#
# Display the information needed for import
#
echo ""
echo "=====================CA Certificate====================="
#cat ${cacert}
$OPENSSL x509 -fingerprint -md5 -in ${cacert}
echo "=====================CA Certificate====================="

echo " "
echo "=====================Client Private key====================="
cat ${encrprivkey}
echo "=====================Client Private key====================="

echo " "
echo "=====================Client certificate====================="
#cat ${certfile}
$OPENSSL x509 -fingerprint -md5 -in ${certfile}
echo "=====================Client certificate====================="

exit 0
