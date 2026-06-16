# Copyright 2026 Praetorian Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License").

PORT ?= 50051

.PHONY: run build clean proto

# run boots the gRPC test server (reflection enabled) on $(PORT).
run:
	GRPC_PORT=$(PORT) go run .

# build compiles the server binary into ./grpc-server.
build:
	go build -o grpc-server .

# clean removes the built binary.
clean:
	rm -f grpc-server

# proto regenerates the Go bindings from labpb/lab.proto.
# Requires protoc, protoc-gen-go, and protoc-gen-go-grpc on $PATH.
proto:
	protoc \
		-I=labpb \
		--go_out=labpb --go_opt=paths=source_relative \
		--go-grpc_out=labpb --go-grpc_opt=paths=source_relative \
		labpb/lab.proto
