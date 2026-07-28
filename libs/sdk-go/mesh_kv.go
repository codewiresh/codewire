package codewire

import (
	"context"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// MeshKVService handles mesh key-value store operations.
type MeshKVService struct {
	client *MeshClient
}

// Set stores a value in the KV store. A zero ttl selects no expiry.
func (s *MeshKVService) Set(ctx context.Context, orgID, networkID, namespace, key string, value []byte, ttl time.Duration) (*MeshKVEntry, error) {
	request := &codewirev1.SetMeshKeyValueRequest{
		OrgId: orgID, NetworkId: networkID, Namespace: namespace, Key: key, Value: append([]byte(nil), value...),
	}
	if ttl != 0 {
		request.Ttl = durationpb.New(ttl)
	}
	response, err := s.client.kvClient.SetMeshKeyValue(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	entry, err := fromProtoMeshKeyValue(response.Msg.GetEntry())
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// Get retrieves a value from the KV store.
func (s *MeshKVService) Get(ctx context.Context, orgID, networkID, namespace, key string) (*MeshKVEntry, error) {
	response, err := s.client.kvClient.GetMeshKeyValue(ctx, connect.NewRequest(&codewirev1.GetMeshKeyValueRequest{
		OrgId: orgID, NetworkId: networkID, Namespace: namespace, Key: key,
	}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	entry, err := fromProtoMeshKeyValue(response.Msg.GetEntry())
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// List returns KV entries matching a prefix.
func (s *MeshKVService) List(ctx context.Context, orgID, networkID, namespace, prefix string) ([]MeshKVEntry, error) {
	var entries []MeshKVEntry
	request := &codewirev1.ListMeshKeyValuesRequest{
		OrgId: orgID, NetworkId: networkID, Namespace: namespace, Prefix: prefix,
	}
	for {
		response, err := s.client.kvClient.ListMeshKeyValues(ctx, connect.NewRequest(request))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, entry := range response.Msg.GetEntries() {
			converted, err := fromProtoMeshKeyValue(entry)
			if err != nil {
				return nil, err
			}
			entries = append(entries, converted)
		}
		request.PageToken = response.Msg.GetNextPageToken()
		if request.PageToken == "" {
			return entries, nil
		}
	}
}

// Delete removes a key from the KV store (owner required).
func (s *MeshKVService) Delete(ctx context.Context, orgID, networkID, namespace, key string) error {
	_, err := s.client.kvClient.DeleteMeshKeyValue(ctx, connect.NewRequest(&codewirev1.DeleteMeshKeyValueRequest{
		OrgId: orgID, NetworkId: networkID, Namespace: namespace, Key: key,
	}))
	return connectSDKError(err)
}
