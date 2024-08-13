package main

import (
	"context"
	"flag"
	"log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	hostPtr := flag.String("host", "127.0.0.1:6443", "apiserver host")
	flag.Parse()
	certFile := "./crttest/test.crt"
	keyFile := "./crttest/test.key"
	caFile := "./crttest/ca.crt"

	config := &rest.Config{
		Host: *hostPtr,
		TLSClientConfig: rest.TLSClientConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
	}
	log.Printf("config.Host:%s", config.Host)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	for _, node := range nodes.Items {
		log.Printf("node:%s", node.Name)
	}
}
