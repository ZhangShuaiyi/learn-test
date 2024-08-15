/*
two terminate:

	./csi-demo
	./csi-node-driver-registrar --plugin-registration-path=/var/lib/kubelet/plugins_registry --csi-address=/var/lib/kubelet/plugins/foo.com/csi.sock --kubelet-registration-path=/var/lib/kubelet/plugins/foo.com/csi.sock --v=5
*/
package main

import (
	"context"
	"net"
	"os"
	"path/filepath"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"k8s.io/klog"
)

var (
	csiDriverName = "foo.com"
	endpointName  = "csi.sock"
)

type identityServer struct {
	csi.UnimplementedIdentityServer
}

type nodeServer struct {
	csi.UnimplementedNodeServer
}

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

func main() {
	socketDir := filepath.Join("/var/lib/kubelet/plugins", csiDriverName)
	if err := os.MkdirAll(socketDir, os.ModePerm); err != nil {
		klog.Errorf("failed to make dir: %s with error: %+v", socketDir, err)
		return
	}
	endpoint := filepath.Join(socketDir, endpointName)
	klog.Infof("Starting Identity Server at: %s\n", endpoint)
	if err := os.Remove(endpoint); err != nil && !os.IsNotExist(err) {
		klog.Fatalf("Failed to remove %s, error: %s", endpoint, err.Error())
	}
	lis, err := net.Listen("unix", endpoint)
	if err != nil {
		klog.Errorf("failed to listen on socket: %s with error: %+v", endpoint, err)
		return
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
