// test/proto-validate is its own module so that protocompile — a dependency of
// a live-test helper, not of the product — stays out of the shipped module's
// require list. Everything under github.com/praetorian-inc/vespasian is consumed
// by downstream SDK users via pkg/sdk, and before this split they resolved and
// downloaded protocompile (and golang.org/x/sync) for a command that only
// validates live-test output.
module github.com/praetorian-inc/vespasian/test/proto-validate

go 1.27.0

require github.com/bufbuild/protocompile v0.14.1

require (
	golang.org/x/sync v0.22.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
