package main

import (
	"context"
	"flag"
	"log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/pkg/api/v1/resource"
)

func main() {
	kubeconfigPtr := flag.String("kubeconfig", "", "Path to the kubeconfig file")
	nodeNamePtr := flag.String("nodeName", "worker-1", "Path to the kubeconfig file")
	flag.Parse()
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfigPath := *kubeconfigPtr
		if config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath); err != nil {
			panic(err.Error())
		}
	}
	log.Printf("config.Host:%s", config.Host)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	pods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{FieldSelector: "spec.nodeName=" + *nodeNamePtr})
	if err != nil {
		panic(err.Error())
	}
	burstablePodCPURequest := int64(0)
	totalPerPodShares := int64(0)
	reuseReqs := make(corev1.ResourceList, 4)
	for _, pod := range pods.Items {
		log.Printf("pod:%s %s", pod.Name, pod.Status.QOSClass)
		if corev1.PodQOSBurstable != pod.Status.QOSClass {
			continue
		}
		req := resource.PodRequests(&pod, resource.PodResourcesOptions{Reuse: reuseReqs})
		if request, found := req[corev1.ResourceCPU]; found {
			burstablePodCPURequest += request.MilliValue()
			totalPerPodShares += request.MilliValue() * 1024 / 1000
		}
	}
	// set burstable shares based on current observe state
	burstableCPUShares := burstablePodCPURequest * 1024 / 1000
	log.Printf("burstablePodCPURequest:%v burstableCPUShares:%v totalPerPodShares:%v", burstablePodCPURequest, burstableCPUShares, totalPerPodShares)
}
