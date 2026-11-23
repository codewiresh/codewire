from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import BinaryIO

from codewire._context import ConnectContext
from codewire._convert import file_entry_to_dict, proto_to_dict
from codewire.errors import CodewireError
from codewire.v1.file_connect import FileServiceClientSync
from codewire.v1.file_pb2 import (
    DownloadFileRequest,
    ListFilesRequest,
    StatFileRequest,
    UploadFileHeader,
    UploadFileRequest,
    WriteFile,
    WriteFilesRequest,
)

# The ErrorInfo reason the platform gives a missing file, as distinct from a
# missing organization or environment.
_FILE_NOT_FOUND = "FILE_NOT_FOUND"


class Files:
    """Typed FileService operations for one environment."""

    def __init__(self, context: ConnectContext, environment_id: str):
        self._context = context
        self._environment_id = environment_id
        self._client = context.transport.client(FileServiceClientSync)

    def list(self, path: str = "/") -> list[dict]:
        request = ListFilesRequest(
            org_id=self._context.resolve_org_id(),
            environment_id=self._environment_id,
            path=path,
        )
        values: list[dict] = []
        while True:
            response = self._context.unary(self._client.list_files, request)
            values.extend(file_entry_to_dict(entry) for entry in response.entries)
            if not response.next_page_token:
                return values
            request.page_token = response.next_page_token

    def stat(self, path: str) -> dict:
        """Return the entry ``list`` shows for ``path``, without listing its
        folder; a final symlink is described as itself. A missing path raises
        ``CodewireError`` with status 404."""
        request = StatFileRequest(
            org_id=self._context.resolve_org_id(),
            environment_id=self._environment_id,
            path=path,
        )
        response = self._context.unary(self._client.stat_file, request)
        return file_entry_to_dict(response.entry)

    def exists(self, path: str) -> bool:
        """Whether ``path`` exists. Only a missing file (404 with reason
        FILE_NOT_FOUND) is False; any other failure, such as an unknown
        organization, is raised."""
        try:
            self.stat(path)
        except CodewireError as error:
            if error.status == 404 and error.reason == _FILE_NOT_FOUND:
                return False
            raise
        return True

    def write_many(
        self, files: Mapping[str, bytes] | Iterable[tuple[str, bytes]]
    ) -> list[dict]:
        """Write every file in one call, at most 1,000 files and 16 MiB in
        all, each as ``upload`` writes one: missing parent folders are made,
        the mode is 0644 and an existing file is replaced. No file is put in
        place until every file is staged. ``files`` maps each path to its
        bytes, or is a list of ``(path, bytes)`` pairs. Returns each file's
        ``path`` and ``size`` in the order given. A request that breaks a rule
        is refused whole with ``CodewireError`` status 400; a larger batch is
        not split."""
        pairs = files.items() if isinstance(files, Mapping) else files
        request = WriteFilesRequest(
            org_id=self._context.resolve_org_id(),
            environment_id=self._environment_id,
            files=[WriteFile(path=path, content=content) for path, content in pairs],
        )
        response = self._context.unary(self._client.write_files, request)
        return [proto_to_dict(file) for file in response.files]

    def upload(self, src: bytes | BinaryIO, remote_path: str) -> None:
        data = src if isinstance(src, bytes) else src.read()
        self._context.client_stream(
            self._client.upload_file, self._upload_requests(data, remote_path)
        )

    def download(self, remote_path: str) -> bytes:
        request = DownloadFileRequest(
            org_id=self._context.resolve_org_id(),
            environment_id=self._environment_id,
            path=remote_path,
        )
        return b"".join(
            response.chunk
            for response in self._context.server_stream(
                self._client.download_file, request
            )
            if response.WhichOneof("payload") == "chunk"
        )

    def _upload_requests(
        self, data: bytes, remote_path: str
    ) -> Iterator[UploadFileRequest]:
        yield UploadFileRequest(
            header=UploadFileHeader(
                org_id=self._context.resolve_org_id(),
                environment_id=self._environment_id,
                path=remote_path,
            )
        )
        if data:
            yield UploadFileRequest(chunk=data)
