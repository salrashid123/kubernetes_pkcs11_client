package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ThalesGroup/crypto11"
	"github.com/salrashid123/pkcssigner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	cacert     = flag.String("cacert", "/home/$USER/.minikube/ca.crt", "RootCA")
	address    = flag.String("address", "https://192.168.49.2:8443", "Address of server")
	clientCert = flag.String("clientCert", "/tmp/myuser.crt", "x509 certificate for the client")
)

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {
	flag.Parse()

	log.Printf("======= Init  ========")

	// var slotNum *int
	// slotNum = new(int)
	// *slotNum = 0

	// softhsm
	// export SOFTHSM2_CONF=/path/to/softhsm.conf
	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		log.Fatal(err)
	}

	defer ctx.Close()

	clientCaCert, err := os.ReadFile(*cacert)
	if err != nil {
		log.Fatal(err)
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	pubPEMData, err := os.ReadFile(*clientCert)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(pubPEMData)
	if err != nil {
		log.Fatal(err)
	}
	filex509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	r, err := pkcssigner.NewPKCSCrypto(&pkcssigner.PKCS{
		Context:         ctx,
		PkcsId:          nil,                 //softhsm
		PkcsLabel:       []byte("keylabel1"), //softhsm
		X509Certificate: filex509,            //softhsm
	})
	if err != nil {
		log.Fatal(err)
	}

	tcert, err := r.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      clientCaCertPool,
			Certificates: []tls.Certificate{tcert},
		},
	}

	kconfig := &rest.Config{
		Host:      *address,
		Transport: tr,
	}

	clientset, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		fmt.Printf("Error creating client: %v", err)
		return 1
	}

	pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error creating client: %v", err)
		return 1
	}

	fmt.Printf("Found %d pods:\n", len(pods.Items))
	for _, pod := range pods.Items {
		fmt.Printf("- [%s] %s\n", pod.Namespace, pod.Name)
	}

	return 0

}
