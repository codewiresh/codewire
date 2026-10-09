"""Actual generated-message streaming with synthetic in-process transport."""
import io
import unittest
from codewire.cw_runtime import CwRuntime, CwRuntimeOutcomeUnknownError, _requests, CHUNK_BYTES
from codewire.v1 import environment_cw_runtime_pb2 as pb


def header(size=CHUNK_BYTES * 3):
    return pb.UpdateEnvironmentCwRuntimeHeader(org_id="org", environment_id="env", request_id="original-request",
        identity=pb.EnvironmentCwRuntimeIdentity(size=size),
        expected_selection=pb.EnvironmentCwRuntimeExpectation(generation=(1 << 64)-1))


class Reader(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.calls=[]
    def read(self, size=-1):
        if not 0 < size <= CHUNK_BYTES:
            raise AssertionError("unbounded read")
        self.calls.append(size)
        return super().read(size)


class FakeContext:
    def __init__(self):
        self.transport=self
        self.calls=[]
        self.fail=False
        self.wrong_ack=False
    def client(self, _):
        return self
    def resolve_org_id(self):
        return "org"
    def update_environment_cw_runtime(self):
        pass
    def rollback_environment_cw_runtime(self):
        pass
    def observe_environment_cw_runtime(self):
        pass
    def client_stream(self, _, requests, **options):
        self.calls.append(("update", options))
        iterator=iter(requests)
        first=next(iterator)
        self.assert_header=first.header
        for request in iterator:
            assert request.WhichOneof("payload")=="chunk" and len(request.chunk)<=CHUNK_BYTES
        if self.fail:
            raise RuntimeError("synthetic lost ACK")
        return pb.UpdateEnvironmentCwRuntimeResponse(operation=pb.EnvironmentCwRuntimeOperation(request_id="another-request" if self.wrong_ack else first.header.request_id,
            expected_selection=first.header.expected_selection,phase="unknown"))
    def unary(self, _, request, **options):
        self.calls.append(("observe",request.request_id))
        return pb.ObserveEnvironmentCwRuntimeResponse(operation=pb.EnvironmentCwRuntimeOperation(request_id=request.request_id,phase="unknown"))


class RuntimeTests(unittest.TestCase):
    def test_laziness_bound_and_full_uint64(self):
        source=Reader(b"x"*(CHUNK_BYTES*3));stream=_requests(header(),source)
        self.assertEqual(source.calls,[]);first=next(stream);self.assertEqual(source.calls,[])
        self.assertEqual(first.header.expected_selection.generation,(1<<64)-1)
        chunks=list(stream);self.assertEqual([len(value.chunk) for value in chunks],[CHUNK_BYTES]*3)
        self.assertEqual(source.calls,[CHUNK_BYTES]*3+[1])
    def test_short_extra_empty_and_oversized_source_refusals(self):
        for source in [Reader(b"x"*63),Reader(b"x"*65)]:
            with self.assertRaises(ValueError):list(_requests(header(64),source))
        for size in [0,63,256*1024*1024+1]:
            with self.assertRaises(ValueError):list(_requests(header(size),Reader(b"")))
    def test_unknown_receipt_is_not_retried_or_changed(self):
        context=FakeContext();runtime=CwRuntime(context,"env");operation=runtime.update(header(64),Reader(b"x"*64))
        self.assertEqual(operation.phase,"unknown");self.assertEqual(operation.expected_selection.generation,(1<<64)-1)
        self.assertEqual(len(context.calls),1)
    def test_lost_ack_keeps_original_request_for_observe_only(self):
        context=FakeContext();context.fail=True;runtime=CwRuntime(context,"env")
        with self.assertRaises(CwRuntimeOutcomeUnknownError) as caught:runtime.update(header(64),Reader(b"x"*64))
        self.assertEqual(caught.exception.request_id,"original-request")
        self.assertEqual(runtime.observe(caught.exception.request_id).phase,"unknown")
        self.assertEqual([value[0] for value in context.calls],["update","observe"])
    def test_scope_mismatch_has_no_transport_or_reader_effect(self):
        context=FakeContext();runtime=CwRuntime(context,"env");source=Reader(b"x"*64);value=header(64);value.environment_id="other"
        with self.assertRaises(ValueError):runtime.update(value,source)
        self.assertEqual(context.calls,[]);self.assertEqual(source.calls,[])
    def test_wrong_ack_preserves_original_request_and_does_not_retry(self):
        context=FakeContext();context.wrong_ack=True;runtime=CwRuntime(context,"env")
        with self.assertRaises(CwRuntimeOutcomeUnknownError) as caught:runtime.update(header(64),Reader(b"x"*64))
        self.assertEqual(caught.exception.request_id,"original-request");self.assertEqual(len(context.calls),1)


if __name__=="__main__":unittest.main()
