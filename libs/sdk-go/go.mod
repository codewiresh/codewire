module codewire.sh/sdk-go

go 1.26.3

require (
	connectrpc.com/connect v1.18.1
	github.com/codewiresh/codewire/libs/gen-go v0.0.0
	google.golang.org/protobuf v1.36.11
)

replace github.com/codewiresh/codewire/libs/gen-go => ../gen-go
