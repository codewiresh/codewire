module codewire.sh/sdk-go/examples/run-agent

go 1.27.3

require codewire.sh/sdk-go v0.0.0

require (
	connectrpc.com/connect v1.18.1 // indirect
	github.com/codewiresh/codewire/libs/gen-go v0.1.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// Built from this repository until the SDK is installed from its release tag
// (codewire#3512).
replace codewire.sh/sdk-go => ../../../sdk-go

replace github.com/codewiresh/codewire/libs/gen-go => ../../../gen-go
