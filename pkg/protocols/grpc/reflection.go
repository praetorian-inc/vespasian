package grpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

// ServiceInfo contains gRPC service metadata
type ServiceInfo struct {
	Name    string
	Methods []MethodInfo
}

// MethodInfo contains gRPC method metadata
type MethodInfo struct {
	Name       string
	InputType  string
	OutputType string
}

// ReflectionClient wraps gRPC reflection protocol
type ReflectionClient struct {
	conn   *grpc.ClientConn
	client grpc_reflection_v1alpha.ServerReflectionClient
}

// NewReflectionClient creates a new reflection client
func NewReflectionClient(target string) (*ReflectionClient, error) {
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)

	return &ReflectionClient{
		conn:   conn,
		client: client,
	}, nil
}

// Close closes the connection
func (c *ReflectionClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ListServices lists all services exposed via reflection
func (c *ReflectionClient) ListServices(ctx context.Context) ([]string, error) {
	stream, err := c.client.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create reflection stream: %w", err)
	}

	req := &grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}

	if err := stream.Send(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	listResp := resp.GetListServicesResponse()
	if listResp == nil {
		return nil, fmt.Errorf("no list services response")
	}

	services := make([]string, 0, len(listResp.Service))
	for _, svc := range listResp.Service {
		services = append(services, svc.Name)
	}

	return services, nil
}

// GetServiceInfo retrieves detailed service information
func (c *ReflectionClient) GetServiceInfo(ctx context.Context, serviceName string) (*ServiceInfo, error) {
	// For now, return basic info
	// Full implementation would use FileDescriptorProto parsing
	return &ServiceInfo{
		Name:    serviceName,
		Methods: []MethodInfo{},
	}, nil
}
