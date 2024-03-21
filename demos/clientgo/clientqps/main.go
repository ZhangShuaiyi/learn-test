package main

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func createPod(clientset *kubernetes.Clientset, name string) (*corev1.Pod, error) {
	var gracePeriod int64 = 2
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      name,
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: &gracePeriod,
			RestartPolicy:                 corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:            "test",
					Image:           "centos:centos7.9.2009",
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"python", "-m", "SimpleHTTPServer"},
				},
			},
		},
	}
	return clientset.CoreV1().Pods("default").Create(context.Background(), &p, metav1.CreateOptions{})
}

func loopGetTest(clientset *kubernetes.Clientset, name string, num int) {
	ctx := context.Background()
	for i := 1; i <= num; i++ {
		_, err := clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			fmt.Println(name, err)
			fmt.Printf("%5d request err:%v\n", i, err)
			// return
		}
	}
}

func main() {
	qos := flag.Int("qos", 5, "client qos")
	burst := flag.Int("burst", 10, "client burst")
	num := flag.Int("num", 100, "request num")
	paral := flag.Int("paral", 1, "paral num")
	flag.Parse()

	config, err := rest.InClusterConfig()
	if err != nil {
		// configFile := "/etc/rancher/k3s/k3s.yaml"
		configFile := "/root/.kube/config"
		if config, err = clientcmd.BuildConfigFromFlags("", configFile); err != nil {
			panic(err.Error())
		}
	}
	config.QPS = float32(*qos)
	config.Burst = *burst
	fmt.Printf("culster host:%s QPS:%f Burst:%d\n", config.Host, config.QPS, config.Burst)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(clientset.CoreV1().RESTClient().GetRateLimiter().QPS())
	for i := 1; i <= *paral; i++ {
		name := fmt.Sprintf("%s%d", "test-qps-pod-", i)
		pod, err := createPod(clientset, name)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(pod.Name)
	}
	var wg sync.WaitGroup
	start := time.Now()
	for i := 1; i <= *paral; i++ {
		wg.Add(1)
		name := fmt.Sprintf("%s%d", "test-qps-pod-", i)
		go func(i int) {
			defer wg.Done()
			ti := time.Now()
			loopGetTest(clientset, name, *num)
			fmt.Printf("  %5d took %v\n", i, time.Since(ti))
		}(i)
	}
	wg.Wait()
	fmt.Printf("took %v\n", time.Since(start))
	for i := 1; i <= *paral; i++ {
		name := fmt.Sprintf("%s%d", "test-qps-pod-", i)
		clientset.CoreV1().Pods("default").Delete(context.Background(), name, metav1.DeleteOptions{})
	}
}
