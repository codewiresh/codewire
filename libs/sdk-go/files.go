package codewire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
)

const fileUploadChunkSize = 32 * 1024

// fileNotFoundReason is the ErrorInfo reason the platform gives a missing
// file, as distinct from a missing organization or environment.
const fileNotFoundReason = "FILE_NOT_FOUND"

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

// Stat returns the entry [Files.List] shows for remotePath, without listing
// its folder; a final symlink is described as itself. A missing path is an
// [*Error] with StatusCode 404.
func (f *Files) Stat(ctx context.Context, remotePath string) (FileEntry, error) {
	response, err := f.client.files.StatFile(ctx, connect.NewRequest(&codewirev1.StatFileRequest{
		OrgId: f.orgID, EnvironmentId: f.envID, Path: remotePath,
	}))
	if err != nil {
		return FileEntry{}, connectSDKError(err)
	}
	return fromProtoFileEntry(response.Msg.GetEntry())
}

// Exists reports whether remotePath exists. Only a missing file (404 with
// reason FILE_NOT_FOUND) is false; any other failure, such as an unknown
// organization, is returned as the error.
func (f *Files) Exists(ctx context.Context, remotePath string) (bool, error) {
	_, err := f.Stat(ctx, remotePath)
	var sdkError *Error
	if errors.As(err, &sdkError) && sdkError.StatusCode == http.StatusNotFound && sdkError.Reason == fileNotFoundReason {
		return false, nil
	}
	return err == nil, err
}

// WriteMany writes every file in one call, at most 1,000 files and 16 MiB in
// all, each as [Files.Upload] writes one: missing parent folders are made,
// the mode is 0644 and an existing file is replaced. No file is put in place
// until every file is staged. It returns each file's path and size in the
// order given. A request that breaks a rule is refused whole, as an [*Error]
// with StatusCode 400; the SDK does not split a larger batch.
func (f *Files) WriteMany(ctx context.Context, files []FileWrite) ([]WrittenFile, error) {
	if err := ensureWriteManyConverterCoverage(); err != nil {
		return nil, err
	}
	request := &codewirev1.WriteFilesRequest{OrgId: f.orgID, EnvironmentId: f.envID}
	for _, file := range files {
		request.Files = append(request.Files, &codewirev1.WriteFile{Path: file.Path, Content: file.Content})
	}
	response, err := f.client.files.WriteFiles(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, connectSDKError(err)
	}
	written := make([]WrittenFile, 0, len(response.Msg.GetFiles()))
	for _, file := range response.Msg.GetFiles() {
		written = append(written, WrittenFile{Path: file.GetPath(), Size: file.GetSize()})
	}
	return written, nil
}
