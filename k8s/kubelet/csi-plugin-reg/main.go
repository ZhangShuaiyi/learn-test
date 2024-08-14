package main

import (
	"context"
	"net"
	"os"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"k8s.io/klog"
	registerapi "k8s.io/kubelet/pkg/apis/pluginregistration/v1"
)

var (
	csiDriverName = "foo.com"
	socketPath    = "/var/lib/kubelet/plugins_registry/foo.com-reg.sock"
	endpoint      = "/var/lib/kubelet/plugins/foo.com/csi.sock"
)

type identityServer struct {
	csi.UnimplementedIdentityServer
}

type nodeServer struct {
	csi.UnimplementedNodeServer
}

type registrationServer struct {
	driverName string
	endpoint   string
	version    []string
}

var _ registerapi.RegistrationServer = registrationServer{}

func (ns *nodeServer) NodeGetInfo(
	ctx context.Context,
	req *csi.NodeGetInfoRequest,
) (*csi.NodeGetInfoResponse, error) {
	klog.Infof("Received NodeGetInfo call: %+v", req)
	return &csi.NodeGetInfoResponse{
		NodeId: "fakenode",
	}, nil
}

// GetPluginInfo returns plugin information.
func (ids *identityServer) GetPluginInfo(
	ctx context.Context,
	req *csi.GetPluginInfoRequest,
) (*csi.GetPluginInfoResponse, error) {
	klog.Infof("Received GetPluginInfo call: %+v", req)
	return &csi.GetPluginInfoResponse{
		Name:          csiDriverName,
		VendorVersion: "0.1",
	}, nil
}

// Probe returns empty response.
func (ids *identityServer) Probe(ctx context.Context, req *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	klog.Infof("Received Probe call: %+v", req)
	return &csi.ProbeResponse{}, nil
}

// GetPluginCapabilities returns plugin capabilities.
func (ids *identityServer) GetPluginCapabilities(
	ctx context.Context,
	req *csi.GetPluginCapabilitiesRequest,
) (*csi.GetPluginCapabilitiesResponse, error) {
	klog.Infof("Received GetPluginCapabilities call: %+v", req)
	return &csi.GetPluginCapabilitiesResponse{
		Capabilities: []*csi.PluginCapability{
			{
				Type: &csi.PluginCapability_Service_{
					Service: &csi.PluginCapability_Service{
						Type: csi.PluginCapability_Service_CONTROLLER_SERVICE,
					},
				},
			},
		},
	}, nil
}

func (e registrationServer) GetInfo(ctx context.Context, req *registerapi.InfoRequest) (*registerapi.PluginInfo, error) {
	klog.Infof("Received GetInfo call: %+v", req)
	return &registerapi.PluginInfo{
		Type:              registerapi.CSIPlugin,
		Name:              e.driverName,
		Endpoint:          e.endpoint,
		SupportedVersions: e.version,
	}, nil
}
func (e registrationServer) NotifyRegistrationStatus(ctx context.Context, status *registerapi.RegistrationStatus) (*registerapi.RegistrationStatusResponse, error) {
	klog.Infof("Received NotifyRegistrationStatus call: %+v", status)
	if !status.PluginRegistered {
		klog.Errorf("Registration process failed with error: %+v, restarting registration container.", status.Error)
		os.Exit(1)
	}
	return &registerapi.RegistrationStatusResponse{}, nil
}

func runCSIServer() {
	klog.Infof("Starting Identity Server at: %s\n", endpoint)
	os.Remove(endpoint)
	lis, err := net.Listen("unix", endpoint)
	if err != nil {
		klog.Errorf("failed to listen on socket: %s with error: %+v", endpoint, err)
		os.Exit(1)
	}
	grpcServer := grpc.NewServer()
	ids := &identityServer{}
	ns := &nodeServer{}

	csi.RegisterIdentityServer(grpcServer, ids)
	csi.RegisterNodeServer(grpcServer, ns)
	err = grpcServer.Serve(lis)
	if err != nil {
		klog.Fatalf("Failed to server: %v", err)
	}
}

func main() {
	registrar := &registrationServer{
		driverName: csiDriverName,
		endpoint:   endpoint,
		version:    []string{"1.0.0"},
	}
	klog.Infof("Starting Registration Server at: %s\n", socketPath)
	os.Remove(socketPath)
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		klog.Errorf("failed to listen on socket: %s with error: %+v", socketPath, err)
		os.Exit(1)
	}
	go runCSIServer()

	grpcServer := grpc.NewServer()
	// Registers kubelet plugin watcher api.
	registerapi.RegisterRegistrationServer(grpcServer, registrar)
	// Starts service
	if err := grpcServer.Serve(lis); err != nil {
		klog.Errorf("Registration Server stopped serving: %v", err)
		os.Exit(1)
	}
	// If gRPC server is gracefully shutdown, exit
	// os.Exit(0)
}
