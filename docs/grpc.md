# gRPC

gRPC is vespasian's fourth target protocol, alongside REST, GraphQL, and
SOAP/WSDL. It captures and classifies gRPC / gRPC-Web traffic, enumerates a
target's services via the Server Reflection Protocol, and generates a proto3
`.proto` specification from the reflected descriptors.

Unlike the other three protocols, gRPC is **opt-in**: its binary HTTP/2 framing
is not auto-detected, so it is never selected by `--api-type auto`. Select it
explicitly with `--api-type grpc`.

## Overview

gRPC support spans the same classify → probe → generate stages as the other
protocols:

| Stage | Package | Role |
|-------|---------|------|
| Classify | `pkg/classify` (`grpc.go`) | Score captured requests as gRPC on content-type, trailers, and path shape |
| Probe | `pkg/probe` (`grpc.go`) | Enumerate services/methods/message types via Server Reflection |
| Generate | `pkg/generate/grpc` | Render the reflected descriptor graph to proto3 `.proto` source |

Two supporting packages back this path:

- **`internal/grpcwire`** — a gRPC length-prefixed framing + protobuf
  wire-format parser (`ParseFrame`, `ParseVarint`, `ParseTag`, `WalkFields`).
  It is foundation reserved for the future traffic-inference path and is not
  yet wired into the classifier, probe, or generator.
- **`test/grpc-server`** — a live Go gRPC server with Server Reflection enabled
  (sample `User`/`Order`/`Account` services, including a server-streaming
  method) used by the reflection-probe tests and the live-test harness.

## Enabling gRPC

gRPC must be requested explicitly. Note the two commands take the API type
differently: `scan` uses the `--api-type` flag, while `generate` takes it as the
first positional argument (`generate <api-type> <capture>`).

```bash
# Full pipeline against a live target (--api-type is a flag on scan).
vespasian scan https://api.example.com:443 --api-type grpc -o service.proto

# Generate from a capture (api-type is positional on generate). Note: this
# re-probes the live gRPC targets recorded in the capture — see below.
vespasian generate grpc capture.json -o service.proto
```

Unlike REST/GraphQL/WSDL, `generate grpc` is **not** a purely offline step and
does not read reflection descriptors from the capture file.
`GRPCReflectionResult.FileDescriptors` is tagged `json:"-"`, so descriptors are
never serialized into `capture.json` (which stores only
`[]crawl.ObservedRequest`). Instead, `generate grpc` re-runs the reflection
probe live against the gRPC targets recorded in the capture, so it requires
`--probe` (on by default) and network reachability to those targets at generate
time. Traffic-only inference is not yet implemented, so a capture whose targets
are unreachable — or run with `--probe=false` — yields no spec. During `scan`,
the same descriptors are produced live by the reflection probe in a single pass.

## Classification

`classify.GRPCClassifier` (`pkg/classify/grpc.go`) scores each captured request.
gRPC normally rides HTTP/2, but proxies and importers frequently flatten
captures to HTTP/1-shaped `ObservedRequest` values, so classification keys off
observable signals rather than the transport:

| Signal | Confidence | Notes |
|--------|-----------|-------|
| Content-Type `application/grpc` / `application/grpc-web*` (request or response) | 0.95 | `GRPCContentTypeConfidence` |
| `grpc-status` / `grpc-message` response trailer header | 0.80 | `GRPCTrailerConfidence` |
| `POST` to a `/<pkg.qualified.Service>/<Method>` path | 0.60 | `GRPCPathConfidence` |
| Content-Type **and** trailer together (HTTP/2 + trailers fingerprint) | 0.99 | `GRPCContentTypeTrailerConfidence` |

A request with none of these signals is not gRPC. When at least one fires, the
combined content-type-plus-trailer case wins; otherwise the highest single
signal sets the confidence.

`DetectAPIType` (auto mode) deliberately instantiates only the REST, WSDL, and
GraphQL classifiers — `GRPCClassifier` is never in that set, so gRPC traffic is
never auto-selected and always resolves to the documented REST default unless
`--api-type grpc` is passed. `TestDetectAPIType_NeverAutoSelectsGRPC` pins that
invariant.

## Probe: Server Reflection

`probe.GRPCProbe` (`pkg/probe/grpc.go`) enumerates a target over the
[gRPC Server Reflection Protocol](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md)
and captures the transitive `FileDescriptorProto` closure for each discovered
service.

- **Version negotiation** — uses `grpcreflect.NewClientAuto`, which negotiates
  the reflection API version with the server (`v1`, with a library-internal
  fallback to the legacy `v1alpha` service).
- **Schema closure** — walks the transitive `FileDescriptorProto` import graph.
  The well-known `google/protobuf/*` files are omitted from generator output
  since any consumer of the `.proto` already has them.
- **Reflection disabled** — when a server is reachable but reflection is off or
  gated, the probe reports a structured reason (`Unimplemented` when reflection
  is not registered; `Unauthenticated` / `PermissionDenied` when it is
  auth-gated) instead of failing silently.
- **Auth-gated reflection** — the probe does not send call credentials/metadata,
  so servers that require auth for reflection are *detected and reported*, not
  bypassed.
- **Descriptor caps (DoS mitigation)** — `walkFileDescriptors` bounds the
  descriptor graph retained per target by both count
  (`classify.MaxGRPCFileDescriptors`, 1000) and aggregate serialized bytes
  (`classify.MaxGRPCDescriptorBytes`, 64 MiB) to cap memory from a hostile or
  pathological server. These bounds are a single source of truth shared with
  the generator's offline path.
- **Endpoint fan-out cap** — reflection dials are bounded by `Config.MaxEndpoints`
  across distinct targets, the same convention as the OPTIONS/Schema/WSDL/GraphQL
  probes.

### SSRF and TLS

- **SSRF** — the dial target is validated before connecting and re-checked at
  connect time via the configurable `Config.Dialer` (default
  `ssrf.SafeDialContext`), closing the DNS-rebinding TOCTOU window — the same
  model as the HTTP probe path. Passing `--dangerous-allow-private` swaps in a
  permissive dialer for private/localhost targets.
- **TLS** — certificates are verified by default. Internal gRPC services often
  present self-signed or internal-CA certificates; to enumerate those, pass
  `--grpc-insecure-skip-verify` to skip verification. SSRF is still enforced by
  the dialer regardless of this flag. Without the flag, a target whose
  certificate fails verification is not enumerated.

## Generator

`generate/grpc.Generator` (`pkg/generate/grpc`) reconstructs the
`FileDescriptorProto` graph captured by the probe and renders deterministic
proto3 source via `jhump/protoreflect`'s `protoprint` (files and elements
sorted for stable output).

- **Reflection required** — generation needs reflection `FileDescriptors`.
  Traffic-only inference is not yet implemented and returns an error, so a
  reflection-disabled target produces no spec.
- **Descriptor caps** — the offline path enforces the same
  `classify.MaxGRPCFileDescriptors` / `classify.MaxGRPCDescriptorBytes` bounds
  as the probe, so a hand-crafted capture file cannot drive unbounded memory
  use.
- **Partial descriptors** — if the reflection result is missing a transitive
  import (e.g. a large import graph truncated at the fetch cap), the generator
  emits every `.proto` it can still link and lists the omitted files in a
  `// WARNING:` header rather than failing the whole generation.
- **Aggregation** — a single capture may hold several gRPC targets (or one
  target observed at multiple URLs); descriptors are merged by `.proto`
  filename, and a byte mismatch for the same filename is surfaced as a conflict
  error rather than silently dropped.

## End-to-end example

The bundled test target (`test/grpc-server`) serves cleartext gRPC with
reflection enabled on `127.0.0.1:50051`. Because it is plaintext on a private
address, the reflection probe needs a synthetic capture that classifies as gRPC
(so it dials the right host:port) plus `--dangerous-allow-private` (so the SSRF
guard permits the loopback dial). This mirrors what `test/run-live-tests.sh`
does:

```bash
# 1. Start the test server (see test/README.md).
# 2. A minimal capture that tags the endpoint as gRPC:
cat > capture.json <<'JSON'
[
  {
    "method": "POST",
    "url": "http://127.0.0.1:50051/lab.v1.UserService/GetUser",
    "headers": { "content-type": "application/grpc" },
    "response": { "status_code": 0, "content_type": "application/grpc" }
  }
]
JSON

# 3. Reflect + generate the .proto (positional api-type; allow the loopback dial):
vespasian generate grpc capture.json --dangerous-allow-private -o lab.proto
```

The generated `lab.proto` declares the discovered services and their RPCs
(including the server-streaming method's `stream` return marker) and compiles
with `protoc`. The live-test harness (`test/run-live-tests.sh`) runs exactly
this flow, then verifies the emitted spec compiles with `protoc`.

For a TLS target presenting a self-signed or internal-CA certificate, add
`--grpc-insecure-skip-verify` (see [SSRF and TLS](#ssrf-and-tls)); it is not
needed for the cleartext test server above.

## See also

- **Wiki tutorial:** [gRPC API Discovery](https://github.com/praetorian-inc/vespasian/wiki/gRPC-API-Discovery)
- **README:** the *gRPC Classification Heuristics* and *gRPC Server Reflection*
  sections, and the CLI reference for `--api-type grpc` /
  `--grpc-insecure-skip-verify`.
- **Package docs:** `pkg/classify`, `pkg/probe`, `pkg/generate/grpc`, and
  `internal/grpcwire` `doc.go` files.
