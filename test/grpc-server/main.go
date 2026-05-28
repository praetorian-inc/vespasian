// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main provides a simple gRPC server for live testing of vespasian.
//
// Registers three reflectable services — UserService (with one server-stream),
// OrderService, and AccountService — defined in lab.proto. Server Reflection
// is enabled so vespasian's GRPCProbe can enumerate everything end-to-end.
//
// Usage:
//
//	go run ./test/grpc-server                # listens on :50051 (or $GRPC_PORT)
//	./grpc-server -port 8993                 # override port via flag
//
// Validate with:
//
//	vespasian probe grpc reflection http://127.0.0.1:50051 --dangerous-allow-private
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/praetorian-inc/vespasian/test/grpc-server/labpb"
)

const defaultPort = "50051"

// userServer implements UserService.
type userServer struct {
	labpb.UnimplementedUserServiceServer
}

func (s *userServer) GetUser(_ context.Context, req *labpb.GetUserRequest) (*labpb.User, error) {
	return &labpb.User{Id: req.GetId(), Name: "Alice", Email: "alice@example.com"}, nil
}

func (s *userServer) ListUsers(_ *labpb.ListUsersRequest, stream labpb.UserService_ListUsersServer) error {
	users := []*labpb.User{
		{Id: "1", Name: "Alice", Email: "alice@example.com"},
		{Id: "2", Name: "Bob", Email: "bob@example.com"},
	}
	for _, u := range users {
		if err := stream.Send(u); err != nil {
			return err
		}
	}
	return nil
}

// orderServer implements OrderService.
type orderServer struct {
	labpb.UnimplementedOrderServiceServer
}

func (s *orderServer) GetOrder(_ context.Context, req *labpb.GetOrderRequest) (*labpb.Order, error) {
	return &labpb.Order{Id: req.GetId(), UserId: "1", Product: "widget", Total: 9.99}, nil
}

// accountServer implements AccountService.
type accountServer struct {
	labpb.UnimplementedAccountServiceServer
}

func (s *accountServer) GetAccount(_ context.Context, req *labpb.GetAccountRequest) (*labpb.Account, error) {
	return &labpb.Account{Id: req.GetId(), Holder: "Alice", Balance: 1234.56}, nil
}

func main() {
	port := flag.String("port", "", "TCP port to listen on (overrides $GRPC_PORT and the default 8993)")
	flag.Parse()

	resolved := *port
	if resolved == "" {
		resolved = os.Getenv("GRPC_PORT")
	}
	if resolved == "" {
		resolved = defaultPort
	}

	lis, err := net.Listen("tcp", "127.0.0.1:"+resolved)
	if err != nil {
		log.Fatalf("listen on :%s failed: %v", resolved, err) //nolint:gosec // G706: test server, log injection N/A
	}

	s := grpc.NewServer()
	labpb.RegisterUserServiceServer(s, &userServer{})
	labpb.RegisterOrderServiceServer(s, &orderServer{})
	labpb.RegisterAccountServiceServer(s, &accountServer{})
	reflection.Register(s)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutting down gracefully")
		s.GracefulStop()
	}()

	log.Printf("gRPC server listening on %s (reflection enabled, services: UserService, OrderService, AccountService)", lis.Addr().String()) //nolint:gosec // G706: test server, log injection N/A
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
