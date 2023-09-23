package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/opencontainers/runc/libcontainer/cgroups/manager"
	libcontainerconfigs "github.com/opencontainers/runc/libcontainer/configs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	defaultTimeout = 5 * time.Second
	// use same message size as cri remote client in kubelet.
	maxMsgSize = 1024 * 1024 * 16
	// unixProtocol is the network protocol of unix socket.
	unixProtocol = "unix"
)

func dial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, unixProtocol, addr)
}

func createCgroup() error {
	config := &libcontainerconfigs.Cgroup{
		Systemd: true,
		Parent:  "kubepods.slice",
		Name:    "critest.slice",
	}

	manager, err := manager.New(config)
	if err != nil {
		return err
	}
	err = manager.Apply(-1)
	if err != nil {
		return err
	}
	return nil
}

func printImages(imageClient runtimeapi.ImageServiceClient) {
	resp, err := imageClient.ListImages(context.Background(), &runtimeapi.ListImagesRequest{})
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, image := range resp.Images {
		fmt.Println(image.Id, image.RepoTags)
	}
}

func generateSandboxConfig() (*runtimeapi.PodSandboxConfig, error) {
	podConfigFile := "pod-config.json"
	sandbox, err := os.ReadFile(podConfigFile)
	if err != nil {
		fmt.Printf("Read %s failed %v\n", podConfigFile, err)
		return nil, err
	}
	sandboxConfig := &runtimeapi.PodSandboxConfig{}

	err = json.Unmarshal(sandbox, sandboxConfig)
	if err != nil {
		fmt.Printf("%s cannot convert to PodSandboxConfig %v\n", podConfigFile, err)
		return nil, err
	}
	sandboxConfig.Linux.CgroupParent = "critest.slice"
	// fmt.Printf("%+v\n", sandboxConfig)
	return sandboxConfig, nil
}

func createPodSandbox(runtimeClient runtimeapi.RuntimeServiceClient, sandboxConfig *runtimeapi.PodSandboxConfig) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// After RunPodSandbox, "ctr c info <PodSandboxId>" can show Pause container info
	// └─critest.slice
	//   └─cri-containerd-bac479c33be8ae46da0d3a9be81a812be441584caa633c3a7c0b5b23d10c7f5f.scope
	//     └─1813842 /pause
	resp, err := runtimeClient.RunPodSandbox(ctx, &runtimeapi.RunPodSandboxRequest{Config: sandboxConfig, RuntimeHandler: "runc"})
	if err != nil {
		return "", err
	}
	return resp.PodSandboxId, nil
}

func createContainer(runtimeClient runtimeapi.RuntimeServiceClient, sandboxConfig *runtimeapi.PodSandboxConfig, sandboxId string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containerConfigFile := "container-config.json"
	container, err := os.ReadFile(containerConfigFile)
	if err != nil {
		fmt.Printf("Read %s failed %v\n", containerConfigFile, err)
		return "", err
	}
	containerConfig := &runtimeapi.ContainerConfig{}
	err = json.Unmarshal(container, containerConfig)
	if err != nil {
		fmt.Printf("%s cannot convert to ContainerConfig %v\n", containerConfigFile, err)
		return "", err
	}

	resp, err := runtimeClient.CreateContainer(ctx, &runtimeapi.CreateContainerRequest{PodSandboxId: sandboxId, SandboxConfig: sandboxConfig, Config: containerConfig})
	if err != nil {
		return "", err
	}
	return resp.ContainerId, nil
}

func startContainer(runtimeClient runtimeapi.RuntimeServiceClient, containerId string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := runtimeClient.StartContainer(ctx, &runtimeapi.StartContainerRequest{ContainerId: containerId})
	if err != nil {
		return err
	}
	return nil
}

func main() {
	// imageEndpoint := "unix:///run/containerd/containerd.sock"
	imageEndpoint := "unix:////run/k3s/containerd/containerd.sock"
	u, err := url.Parse(imageEndpoint)
	if err != nil {
		fmt.Println(err)
		return
	}
	addr := u.Path
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dial),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(conn.Target())
	err = createCgroup()
	if err != nil {
		fmt.Printf("createCgroup failed: %v\n", err)
	}
	// imageClient := runtimeapi.NewImageServiceClient(conn)
	// printImages(imageClient)

	runtimeClient := runtimeapi.NewRuntimeServiceClient(conn)
	sandboxConfig, err := generateSandboxConfig()
	if err != nil {
		fmt.Printf("generateSandboxConfig failed: %v\n", err)
		return
	}
	sandboxId, err := createPodSandbox(runtimeClient, sandboxConfig)
	if err != nil {
		fmt.Printf("create PodSandbox failed:%v\n", err)
		return
	}
	fmt.Printf("sandboxId:%s\n", sandboxId)
	containerId, err := createContainer(runtimeClient, sandboxConfig, sandboxId)
	if err != nil {
		fmt.Printf("create Container failed:%v\n", err)
		return
	}
	fmt.Printf("containerId:%s created\n", containerId)

	err = startContainer(runtimeClient, containerId)
	if err != nil {
		fmt.Printf("start Container failed:%v\n", err)
		return
	}
	fmt.Printf("containerId:%s started\n", containerId)
}
