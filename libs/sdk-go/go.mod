module codewire.sh/sdk-go

go 1.27.3

require (
	connectrpc.com/connect v1.18.1
	github.com/codewiresh/codewire/libs/gen-go v0.1.0
	google.golang.org/protobuf v1.36.11
)

// The published module requires gen-go v0.1.0 by its tag libs/gen-go/v0.1.0
// (codewire#3512); inside this repository it builds from the sibling tree.
replace github.com/codewiresh/codewire/libs/gen-go => ../gen-go
