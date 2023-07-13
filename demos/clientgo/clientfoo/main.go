package main

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func list_pod(clientset *kubernetes.Clientset) {
	pods, err := clientset.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	for _, pod := range pods.Items {
		fmt.Printf("pod %s : %s\n", pod.Name, pod.Status.Phase)
	}
}

func main() {
	name := "clientfoo"
	config, err := rest.InClusterConfig()
	if err != nil {
		if config, err = clientcmd.BuildConfigFromFlags("", "/etc/rancher/k3s/k3s.yaml"); err != nil {
			panic(err.Error())
		}
	}
	config.UserAgent = name
	fmt.Printf("culster host:%s\n", config.Host)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	list_pod(clientset)

	pod, err := clientset.CoreV1().Pods("default").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	dt := time.Now()
	if pod.ObjectMeta.Annotations == nil {
		pod.ObjectMeta.Annotations = make(map[string]string, 0)
	}
	fmt.Printf("old pod %s annotations:%s\n", pod.Name, pod.GetAnnotations())
	pod.ObjectMeta.Annotations["test_time"] = dt.String()
	fmt.Printf("    pod %s annotations changeto :%s\n", pod.Name, pod.GetAnnotations())
	new, err := clientset.CoreV1().Pods("default").Update(context.Background(), pod, metav1.UpdateOptions{})
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("new pod %s annotations:%s\n", new.Name, new.GetAnnotations())
}
