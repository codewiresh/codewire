//! File transfer calls on [`CodewireClient`] through the generated
//! `FileService` client.

use crate::*;

impl CodewireClient {
    pub async fn list_files(
        &self,
        request: ListFilesRequest,
    ) -> Result<ListFilesResponse, ClientError> {
        self.files
            .list_files_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// The entry `list_files` shows for one path, without listing its
    /// folder; a final symlink is described as itself. A missing path is
    /// `NotFound`.
    pub async fn stat_file(
        &self,
        request: StatFileRequest,
    ) -> Result<StatFileResponse, ClientError> {
        self.files
            .stat_file_with_options(request, self.session_unary_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// The file's frames as they arrive, so a caller can write a large file
    /// without holding it (#3968).
    pub async fn download_file(
        &self,
        request: DownloadFileRequest,
    ) -> Result<
        impl futures_util::Stream<Item = Result<DownloadFileResponse, ClientError>> + Send + use<>,
        ClientError,
    > {
        let stream = self
            .files
            .download_file_with_options(request, self.auth_options().await?)
            .await
            .map_err(ClientError::from)?;
        Ok(futures_util::stream::try_unfold(
            stream,
            |mut stream| async move {
                let message = stream
                    .message::<DownloadFileResponse>()
                    .await
                    .map_err(ClientError::from)?
                    .map(|message| message.to_owned_message());
                Ok(message.map(|message| (message, stream)))
            },
        ))
    }

    /// Sends the requests as the stream yields them; a stream that stops
    /// without ending holds the call open until the caller drops it, which
    /// aborts the upload (#3968).
    pub async fn upload_file(
        &self,
        requests: impl futures_util::Stream<Item = UploadFileRequest> + Send + 'static,
    ) -> Result<UploadFileResponse, ClientError> {
        self.files
            .upload_file_with_options(requests, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// One part of a resumable upload (#4373), sent as the stream yields it.
    pub async fn upload_file_part(
        &self,
        requests: impl futures_util::Stream<Item = UploadFilePartRequest> + Send + 'static,
    ) -> Result<UploadFilePartResponse, ClientError> {
        self.files
            .upload_file_part_with_options(requests, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}
