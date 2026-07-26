package codewire

import (
	"context"
	"fmt"
	"io"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

const fileUploadChunkSize = 32 * 1024

// Files provides file operations on an environment through FileService.
type Files struct {
	client *Client
	orgID  string
	envID  string
}

type downloadReadCloser struct {
	reader *io.PipeReader
	cancel context.CancelFunc
}

func (r *downloadReadCloser) Read(buffer []byte) (int, error) {
	return r.reader.Read(buffer)
}

func (r *downloadReadCloser) Close() error {
	r.cancel()
	return r.reader.Close()
}

func newFiles(client *Client, orgID, envID string) *Files {
	return &Files{client: client, orgID: orgID, envID: envID}
}

// Upload streams the given reader to the environment at remotePath.
func (f *Files) Upload(ctx context.Context, src io.Reader, remotePath string) error {
	stream := f.client.files.UploadFile(ctx)
	if err := stream.Send(&codewirev1.UploadFileRequest{
		Payload: &codewirev1.UploadFileRequest_Header{Header: &codewirev1.UploadFileHeader{
			OrgId: f.orgID, EnvironmentId: f.envID, Path: remotePath,
		}},
	}); err != nil {
		return connectSDKError(err)
	}
	buffer := make([]byte, fileUploadChunkSize)
	for {
		read, err := src.Read(buffer)
		if read > 0 {
			chunk := append([]byte(nil), buffer[:read]...)
			if sendErr := stream.Send(&codewirev1.UploadFileRequest{
				Payload: &codewirev1.UploadFileRequest_Chunk{Chunk: chunk},
			}); sendErr != nil {
				return connectSDKError(sendErr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("codewire: read file: %w", err)
		}
	}
	_, err := stream.CloseAndReceive()
	return connectSDKError(err)
}

// Download retrieves a file from the single FileService DownloadFile RPC.
func (f *Files) Download(ctx context.Context, remotePath string) (io.ReadCloser, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := f.client.files.DownloadFile(streamCtx, connect.NewRequest(&codewirev1.DownloadFileRequest{
		OrgId: f.orgID, EnvironmentId: f.envID, Path: remotePath,
	}))
	if err != nil {
		cancel()
		return nil, connectSDKError(err)
	}
	reader, writer := io.Pipe()
	go func() {
		defer cancel()
		for stream.Receive() {
			if _, err := writer.Write(stream.Msg().GetChunk()); err != nil {
				_ = writer.CloseWithError(err)
				return
			}
		}
		if err := stream.Err(); err != nil {
			_ = writer.CloseWithError(connectSDKError(err))
			return
		}
		_ = writer.Close()
	}()
	return &downloadReadCloser{reader: reader, cancel: cancel}, nil
}

// List returns directory entries at dirPath (or the workspace root if nil).
func (f *Files) List(ctx context.Context, dirPath *string) ([]FileEntry, error) {
	req := &codewirev1.ListFilesRequest{
		OrgId: f.orgID, EnvironmentId: f.envID, Path: valueOrEmpty(dirPath),
	}
	var entries []FileEntry
	for {
		response, err := f.client.files.ListFiles(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, connectSDKError(err)
		}
		for _, entry := range response.Msg.GetEntries() {
			converted, err := fromProtoFileEntry(entry)
			if err != nil {
				return nil, err
			}
			entries = append(entries, converted)
		}
		req.PageToken = response.Msg.GetNextPageToken()
		if req.PageToken == "" {
			return entries, nil
		}
	}
}
