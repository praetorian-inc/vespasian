# grpc-server

Live test target for Vespasian's gRPC discovery. Registers three reflectable services defined in `labpb/lab.proto`:

| Service | Methods | Notes |
|---|---|---|
| `lab.v1.UserService` | `GetUser`, `ListUsers` | `ListUsers` is server-streaming |
| `lab.v1.OrderService` | `GetOrder` | Unary |
| `lab.v1.AccountService` | `GetAccount` | Unary |

Server Reflection (v1 + v1alpha) is enabled, so `vespasian probe grpc reflection` enumerates the full surface end-to-end.

## Run

```bash
# Default port (50051, or $GRPC_PORT)
make -C test/grpc-server run

# Custom port
make -C test/grpc-server run PORT=8993
# or directly:
go run ./test/grpc-server -port 8993
```

## Verify with grpcurl

```bash
grpcurl -plaintext localhost:50051 list
# lab.v1.AccountService
# lab.v1.OrderService
# lab.v1.UserService
# grpc.reflection.v1.ServerReflection
# grpc.reflection.v1alpha.ServerReflection
```

## Verify with vespasian

```bash
# Build vespasian
make build

# Probe and emit .proto
./bin/vespasian probe grpc reflection http://127.0.0.1:50051 \
    --dangerous-allow-private -o /tmp/lab.proto

# Round-trip through protoc
protoc --proto_path=/tmp --descriptor_set_out=/dev/null /tmp/lab.proto && echo OK
```

## Regenerate bindings

`labpb/lab.pb.go` and `labpb/lab_grpc.pb.go` are committed. Regenerate after editing `lab.proto`:

```bash
protoc \
    -I=test/grpc-server/labpb \
    --go_out=test/grpc-server/labpb --go_opt=paths=source_relative \
    --go-grpc_out=test/grpc-server/labpb --go-grpc_opt=paths=source_relative \
    test/grpc-server/labpb/lab.proto
```

Requires `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc` on `$PATH`.

## Live-test harness integration

Wired into `setup-live-targets.sh` and `run-live-tests.sh` as the `grpc-server`
target. Unlike the HTTP targets it is not crawled (browsers cannot speak gRPC);
instead the harness runs `vespasian probe grpc reflection` against it and
validates the emitted `.proto` against `expected-paths.json`.

```bash
./test/setup-live-targets.sh --targets grpc-server   # build + start on :50051
./test/run-live-tests.sh --targets grpc-server        # probe + validate
./test/setup-live-targets.sh --teardown               # stop + clean up
```

Readiness is checked with `grpcurl` (falling back to `nc`/`/dev/tcp`) rather
than an HTTP health poll.
