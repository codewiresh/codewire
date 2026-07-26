//! Connect-RPC adapter for sandbox file operations.
//!
//! REST and Connect use the same SFTP/exec service layer in `api::proxy`.
//! This module owns only protobuf mapping, streaming protocol validation, and
//! the documented Connect normalization for missing files/directories.

use std::borrow::Cow;
use std::sync::Arc;

use axum::http::StatusCode;
use buffa_types::Timestamp;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::connect::{auth_user, wire_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use futures::StreamExt;

use crate::api::ApiState;
use crate::api::proxy::{
    CONNECT_SFTP_REQUEST_TIMEOUT_SECS, WorkspaceFileEntry, WorkspaceFileReadError,
    begin_workspace_file_upload, list_workspace_files, prepare_workspace_file_download,
};
use crate::connect::{rendered_workspace_error, workspace_rpc_error};

pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(FileConnectService { state }))
}

struct FileConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl proto::FileService for FileConnectService {
    async fn list_files(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListFilesRequest>,
    ) -> ServiceResult<proto::ListFilesResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_coordinates(request.org_id, request.environment_id, None)
            .and_then(|()| validate_pagination(request.page_token))
            .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let entries = list_workspace_files(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.path,
            Some(CONNECT_SFTP_REQUEST_TIMEOUT_SECS),
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::ListFilesResponse {
            entries: entries.into_iter().map(proto_file_entry).collect(),
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn download_file(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::DownloadFileRequest>,
    ) -> ServiceResult<ServiceStream<proto::DownloadFileResponse>> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        validate_coordinates(
            &request.org_id,
            &request.environment_id,
            Some(&request.path),
        )
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;
        let download = prepare_workspace_file_download(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            &request.path,
        )
        .await
        .map_err(|error| file_read_rpc_error(error, &ctx))?;
        let info = proto_file_entry(download.entry.clone());
        let request_id = request_id(&ctx).map(str::to_owned);

        let stream = futures::stream::unfold(
            (Some(info), Some(download)),
            move |(pending_info, mut download)| {
                let request_id = request_id.clone();
                async move {
                    if let Some(info) = pending_info {
                        return Some((
                            Ok(proto::DownloadFileResponse {
                                payload: Some(proto::download_file_response::Payload::Info(
                                    Box::new(info),
                                )),
                                ..Default::default()
                            }),
                            (None, download),
                        ));
                    }

                    let active_download = download.as_mut()?;
                    match active_download.next_chunk().await {
                        Ok(Some(chunk)) => Some((
                            Ok(proto::DownloadFileResponse {
                                payload: Some(proto::download_file_response::Payload::Chunk(chunk)),
                                ..Default::default()
                            }),
                            (None, download),
                        )),
                        Ok(None) => None,
                        Err(error) => Some((
                            Err(wire_error(&rendered_workspace_error(
                                &error,
                                request_id.as_deref(),
                            ))),
                            (None, None),
                        )),
                    }
                }
            },
        );
        connectrpc::Response::stream_ok(stream)
    }

    async fn upload_file(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::UploadFileRequest>,
    ) -> ServiceResult<proto::UploadFileResponse> {
        let user = auth_user(&ctx)?.clone();
        let first = match requests.next().await {
            Some(Ok(message)) => message.to_owned_message(),
            Some(Err(error)) => return Err(error),
            None => {
                return Err(workspace_rpc_error(
                    &protocol_error("/payload", "header must be the first message"),
                    &ctx,
                ));
            }
        };
        let header = match first.payload {
            Some(proto::upload_file_request::Payload::Header(header)) => header,
            _ => {
                return Err(workspace_rpc_error(
                    &protocol_error("/payload", "header must be the first message"),
                    &ctx,
                ));
            }
        };
        validate_upload_header(&header.org_id, &header.environment_id, &header.path)
            .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        let mut upload = begin_workspace_file_upload(
            &self.state,
            &user,
            &header.org_id,
            &header.environment_id,
            &header.path,
            Some(CONNECT_SFTP_REQUEST_TIMEOUT_SECS),
        )
        .await
        .map_err(|error| workspace_rpc_error(&error, &ctx))?;

        while let Some(message) = requests.next().await {
            let message = match message {
                Ok(message) => message.to_owned_message(),
                Err(error) => {
                    upload.abort().await;
                    return Err(error);
                }
            };
            let chunk = match message.payload {
                Some(proto::upload_file_request::Payload::Chunk(chunk)) => chunk,
                Some(proto::upload_file_request::Payload::Header(_)) => {
                    let error = protocol_error("/payload/header", "must appear only once");
                    upload.abort().await;
                    return Err(workspace_rpc_error(&error, &ctx));
                }
                None => {
                    let error = protocol_error("/payload", "is required");
                    upload.abort().await;
                    return Err(workspace_rpc_error(&error, &ctx));
                }
            };
            if let Err(error) = upload.write_chunk(&chunk).await {
                upload.abort().await;
                return Err(workspace_rpc_error(&error, &ctx));
            }
        }

        let result = match upload.finish().await {
            Ok(result) => result,
            Err(error) => {
                upload.abort().await;
                return Err(workspace_rpc_error(&error, &ctx));
            }
        };
        connectrpc::Response::ok(proto::UploadFileResponse {
            path: result.path,
            size: result.size,
            ..Default::default()
        })
    }
}

fn validate_coordinates(org_id: &str, environment_id: &str, path: Option<&str>) -> AppResult<()> {
    validate_coordinates_at(
        org_id,
        environment_id,
        path,
        "/org_id",
        "/environment_id",
        "/path",
    )
}

fn validate_upload_header(org_id: &str, environment_id: &str, path: &str) -> AppResult<()> {
    validate_coordinates_at(
        org_id,
        environment_id,
        Some(path),
        "/header/org_id",
        "/header/environment_id",
        "/header/path",
    )
}

fn validate_coordinates_at(
    org_id: &str,
    environment_id: &str,
    path: Option<&str>,
    org_path: &'static str,
    environment_path: &'static str,
    file_path: &'static str,
) -> AppResult<()> {
    let mut errors = Vec::new();
    if org_id.trim().is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed(org_path),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if environment_id.trim().is_empty() {
        errors.push(ValidationIssue {
            path: Cow::Borrowed(environment_path),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if path.is_some_and(|path| path.trim().is_empty()) {
        errors.push(ValidationIssue {
            path: Cow::Borrowed(file_path),
            message: Cow::Borrowed("must not be empty"),
        });
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

fn validate_pagination(page_token: &str) -> AppResult<()> {
    if page_token.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest("unrecognized page_token".into()))
    }
}

fn protocol_error(path: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        errors: vec![ValidationIssue {
            path: Cow::Borrowed(path),
            message: Cow::Borrowed(message),
        }],
    }
}

fn proto_file_entry(entry: WorkspaceFileEntry) -> proto::FileEntry {
    proto::FileEntry {
        name: entry.name,
        size: entry.size,
        is_dir: entry.is_dir,
        mode: entry.mode,
        mod_time: entry
            .mod_time
            .map(|seconds| Timestamp::from_unix(seconds as i64, 0))
            .into(),
        ..Default::default()
    }
}

fn file_read_app_error(error: WorkspaceFileReadError) -> AppError {
    match error {
        WorkspaceFileReadError::App(error) => error,
        WorkspaceFileReadError::Missing { detail, .. }
        | WorkspaceFileReadError::CommandFailed(detail) => AppError::Coded {
            status: StatusCode::NOT_FOUND,
            code: "file_not_found",
            detail: if detail.is_empty() {
                Cow::Borrowed("file not found")
            } else {
                Cow::Owned(detail)
            },
        },
        WorkspaceFileReadError::Directory => AppError::Coded {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_path",
            detail: Cow::Borrowed("path is a directory"),
        },
    }
}

fn file_read_rpc_error(
    error: WorkspaceFileReadError,
    ctx: &RequestContext,
) -> connectrpc::ConnectError {
    workspace_rpc_error(&file_read_app_error(error), ctx)
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::connect_error::{ConnectCode, ConnectErrorDetail};

    #[test]
    fn coordinate_validation_allows_default_list_path() {
        assert!(validate_coordinates("org", "env", None).is_ok());
        let error = validate_coordinates("", "", Some(" ")).unwrap_err();
        let AppError::Validation { errors } = error else {
            panic!("expected validation error");
        };
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0].path, "/org_id");
        assert_eq!(errors[1].path, "/environment_id");
        assert_eq!(errors[2].path, "/path");
    }

    #[test]
    fn download_errors_have_stable_codes_and_details() {
        let missing = file_read_app_error(WorkspaceFileReadError::Missing {
            operation: "stat",
            detail: "gone".into(),
        });
        let rendered = rendered_workspace_error(&missing, Some("req-file"));
        assert_eq!(rendered.code, ConnectCode::NotFound);
        assert!(rendered.details.iter().any(|detail| matches!(
            detail,
            ConnectErrorDetail::ErrorInfo(info)
                if info.reason == "FILE_NOT_FOUND"
                    && info.metadata.get("request_id").map(String::as_str) == Some("req-file")
        )));

        let directory = file_read_app_error(WorkspaceFileReadError::Directory);
        let rendered = rendered_workspace_error(&directory, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        assert!(rendered.details.iter().any(|detail| matches!(
            detail,
            ConnectErrorDetail::ErrorInfo(info) if info.reason == "INVALID_PATH"
        )));
    }

    #[test]
    fn entry_mapping_keeps_raw_mode_and_timestamp() {
        let entry = proto_file_entry(WorkspaceFileEntry {
            name: "run.sh".into(),
            size: 7,
            is_dir: false,
            mode: 0o100755,
            mod_time: Some(1_700_000_000),
        });
        assert_eq!(entry.mode, 0o100755);
        assert!(entry.mod_time.is_set());
        assert_eq!(entry.mod_time.seconds, 1_700_000_000);
    }

    #[test]
    fn upload_protocol_errors_are_field_violations() {
        let error = protocol_error("/payload/header", "must appear only once");
        let rendered = rendered_workspace_error(&error, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        assert!(rendered.details.iter().any(|detail| matches!(
            detail,
            ConnectErrorDetail::BadRequest(bad_request)
                if bad_request.field_violations[0].field == "payload.header"
        )));

        let error = validate_upload_header("", "", "").unwrap_err();
        let rendered = rendered_workspace_error(&error, None);
        assert!(rendered.details.iter().any(|detail| matches!(
            detail,
            ConnectErrorDetail::BadRequest(bad_request)
                if bad_request.field_violations.iter().map(|violation| violation.field.as_str()).collect::<Vec<_>>()
                    == ["header.org_id", "header.environment_id", "header.path"]
        )));
    }
}
