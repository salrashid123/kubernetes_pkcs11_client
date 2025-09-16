### Kubernetes Certificate Auth using PKCS-11 Keys

Simple demo of authenticating to kubernetes API using client certficates embedded inside a PKCS-11 device

When you authenticate to kubernetes api using [client certificates](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#x509-client-certificates), the private key is still visible on the filesystem or within the kubernetes config file.

This poses some risk becuase the keys can be stolen or copied out of the disk.

The variation described in this sample shows how you can use keys saved on a PKCS.

also see:

* [Kubernetes Certificate Auth using Trusted Platform Module (TPM) keys](https://github.com/salrashid123/kubernetes_tpm_client)
* [mTLS with PKCS11](https://github.com/salrashid123/mtls_pkcs11)
* [crypto.Signer for PKCS11](https://github.com/salrashid123/pkcssigner)

---

### References

* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
* [crypto.Signer, implementations for Trusted Platform Modules](https://github.com/salrashid123/tpmsigner)

### Setup

### Install PKCS11 support and Verify with OpenSSL

The following will install and test softHSM using openssl.  Once this is done, we will use the golang mTLS clients to establish client-server communication.

#### Install openssl with pkcs11 

First install openssl with its [PKCS11 engine](https://github.com/OpenSC/libp11#openssl-engines).

TODO, use openssl providers  

On debian

```bash
# add to /etc/apt/sources.list
  deb http://http.us.debian.org/debian/ testing non-free contrib main

# then
$ export DEBIAN_FRONTEND=noninteractive 
$ apt-get update && apt-get install libtpm2-pkcs11-1 tpm2-tools libengine-pkcs11-openssl opensc softhsm2 libsofthsm2 pkcs11-provider -y
```

Note, the installation above adds in the libraries for all modules in this repo (TPM, OpenSC, etc)..you may only need `libengine-pkcs11-openssl` here to verify

Once installed, you can check that it can be loaded:

Set the pkcs11 provider and module directly into openssl (make sure `libpkcs11.so` engine reference exists first!)


Verify the path,

```bash
# edit `/etc/ssl/openssl.cnf`

```bash
openssl_conf = openssl_def
[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so  ## verify this exists
```


```bash

$ openssl engine
  (rdrand) Intel RDRAND engine
  (dynamic) Dynamic engine loading support

$ openssl engine -t -c pkcs11
  (pkcs11) pkcs11 engine
      [ available ]

## TODO: use providers but it doens' work well (https://github.com/latchset/pkcs11-provider/issues/634)
# $ openssl list  -provider pkcs11  -provider default  --providers
# Providers:
#   default
#     name: OpenSSL Default Provider
#     version: 3.5.0
#     status: active
#   pkcs11
#     name: PKCS#11 Provider
#     version: 3.5.0
#     status: active

```

---

#### SOFTHSM

SoftHSM is as the name suggests, a sofware "HSM" module used for testing.   It is ofcourse not hardware backed but the module does allow for a PKCS11 interface which we will also use for testing.

First make sure the softhsm library is installed

- [SoftHSM Install](https://www.opendnssec.org/softhsm/)

Setup a config file where the `directories.tokendir` points to a existing folder where softHSM will save all its data (in this case its `misc/tokens/`)

>> This repo already contains a sample configuration/certs to use with the softhsm token directory...just delete the folder and start from scratch if you want..

Now, make sure that the installation created the softhsm module for openssl:  `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`


```bash
openssl engine dynamic \
 -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so \
 -pre ID:pkcs11 -pre LIST_ADD:1 \
 -pre LOAD \
 -pre MODULE_PATH:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
 -t -c

  (dynamic) Dynamic engine loading support
  [Success]: SO_PATH:/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
  [Success]: ID:pkcs11
  [Success]: LIST_ADD:1
  [Success]: LOAD
  [Success]: MODULE_PATH:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
  Loaded: (pkcs11) pkcs11 engine
  [RSA, rsaEncryption, id-ecPublicKey]
      [ available ]
```

Use [pkcs11-too](https://manpages.debian.org/testing/opensc/pkcs11-tool.1.en.html) which comes with the installation of opensc

```bash
export SOFTHSM2_CONF=/absolute/path/to/kubernetes_pkcs11_client/example/softhsm.conf
rm -rf /tmp/tokens
mkdir /tmp/tokens

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
        Available slots:
        Slot 0 (0x2593104d): SoftHSM slot ID 0x2593104d
          token label        : token1
          token manufacturer : SoftHSM project
          token model        : SoftHSM v2
          token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
          hardware version   : 2.6
          firmware version   : 2.6
          serial num         : 2c6106832593104d
          pin min/max        : 4/255
        Slot 1 (0x1): SoftHSM slot ID 0x1
          token state:   uninitialized



### >>> Important NOTE the serial num   2c6106832593104d  
## we will use this in the PKCS-11 URI

# Create  private key as id=4142, keylabel1;  
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects

## get the serial number from the previous --list-token-slots command
export serial_number="2d2033d0a5540a04"
### Use openssl module to sign and print the public key (not, your serial number will be different)

# client
export PKCS11_CLIENT_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_CLIENT_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=public;object=keylabel1?pin-value=mynewpin"

### Display the public key
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_CLIENT_PUBLIC_KEY" -pubout

### Sign and verify
echo "sig data" > /tmp/data.txt
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_CLIENT_PUBLIC_KEY" -pubout -out /tmp/pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine  -inkey $PKCS11_CLIENT_PRIVATE_KEY -sign -in /tmp/data.txt -out /tmp/data.sig
openssl pkeyutl -pubin -inkey /tmp/pub.pem -verify -in /tmp/data.txt -sigfile /tmp/data.sig
```

Now that we have a key on the TPM, issue an x509:

```bash

openssl rsa -engine pkcs11 --inform engine  -in "$PKCS11_CLIENT_PRIVATE_KEY" -pubout > /tmp/svc_account_pkcs_pem.pub
openssl req -engine pkcs11 --keyform engine  -subj "/CN=myuser" -new -key "$PKCS11_CLIENT_PRIVATE_KEY" -out /tmp/svc_account_pkcs.csr
openssl req -in /tmp/svc_account_pkcs.csr  -text -noout -verify
```

Now start minikube and install associate the certificate with a user.  The steps we're following here is the same as shown [here](https://kubernetes.io/docs/tasks/tls/certificate-issue-client-csr/)


```bash
minikube start

export CSR=`cat /tmp/svc_account_pkcs.csr | base64 | tr -d "\n"`
envsubst < "kcsr.tmpl" > "/tmp/kcsr.yaml"
kubectl apply -f /tmp/kcsr.yaml

kubectl get csr

kubectl certificate approve myuser

kubectl get csr/myuser -o yaml
kubectl get csr myuser -o jsonpath='{.status.certificate}'| base64 -d > /tmp/myuser.crt

kubectl create role developer --verb=create --verb=get --verb=list --verb=update --verb=delete --resource=pods
kubectl create rolebinding developer-binding-myuser --role=developer --user=myuser
```

Ok, now that we have the certificate setup on the cluster, we'll run the client which just lists pods:

```bash
$ kubectl cluster-info
   Kubernetes control plane is running at https://192.168.49.2:8443

$ go run main.go --address="https://192.168.49.2:8443" \
   --cacert="$HOME/.minikube/ca.crt" --clientCert="/tmp/myuser.crt" 

Found 0 pods:
```

Note that the example above create a key _on the tpm_ but you can certainly import a key or duplicate and transfer:

* [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)

### using curl and openssl

Note, curl needs to be build with engine support

for openssl: 
```bash
export OPENSSL_CONF=`pwd`/example/openssl.cnf
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/

openssl s_client -cert /tmp/myuser.crt \
  -key $PKCS11_CLIENT_PRIVATE_KEY -keyform engine -engine pkcs11 \
   -connect 192.168.49.2:8443 -CAfile $HOME/.minikube/ca.crt -tlsextdebug

### then enter in the GET request and host header
GET /api/v1/namespaces/default/pods?limit=500 HTTP/1.1
Host: 192.168.49.2

HTTP/1.1 200 OK
Audit-Id: 0cabee3a-0297-467b-abf4-4e732c6b06a1
Cache-Control: no-cache, private
Content-Type: application/json
X-Kubernetes-Pf-Flowschema-Uid: e8131bf2-f5a7-4a62-97e9-38ef17e19b5b
X-Kubernetes-Pf-Prioritylevel-Uid: 12f82a86-1190-4772-96a6-959b12e268bf
Date: Tue, 16 Sep 2025 10:58:39 GMT
Content-Length: 86

{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"2244"},"items":[]}

```

```bash
export OPENSSL_CONF=`pwd`/example/openssl.cnf
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/

$ curl --engine list
$ curl --engine pkcs11  --key-type ENG --cacert $HOME/.minikube/ca.crt --cert /tmp/myuser.crt \
   --key $PKCS11_CLIENT_PRIVATE_KEY 'https://192.168.49.2:8443/api/v1/namespaces/default/pods?limit=500'
```



#### TODO:

implement pkcs-11:

* [kubectl pkcs11 smartcard support #64783](https://github.com/kubernetes/kubernetes/issues/64783)
* [mTLS with PKCS11](https://github.com/salrashid123/mtls_pkcs11)
