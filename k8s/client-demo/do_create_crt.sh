mkdir -p crttest
pushd crttest
openssl genrsa -out test.key 2048
openssl req -new -key test.key -out test.csr -subj "/CN=system:node:testdev/O=system:nodes"
openssl x509 -req -in test.csr \
  -CA /etc/kubernetes/pki/ca.crt \
  -CAkey /etc/kubernetes/pki/ca.key \
  -CAcreateserial -out test.crt -days 7300
cp /etc/kubernetes/pki/ca.crt .
popd
