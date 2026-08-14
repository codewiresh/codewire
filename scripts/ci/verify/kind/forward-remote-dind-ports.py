#!/usr/bin/env python3
"""Loopback-only TCP forwarding for a Kind cluster on a remote DinD daemon."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
from dataclasses import dataclass


@dataclass(frozen=True)
class Forward:
    listen_port: int
    target_port: int


def port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def forward(value: str) -> Forward:
    listen, separator, target = value.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("forward must be LISTEN_PORT:TARGET_PORT")
    return Forward(port(listen), port(target))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--forward", action="append", type=forward, required=True)
    args = parser.parse_args()
    listen_ports = [item.listen_port for item in args.forward]
    if len(listen_ports) != len(set(listen_ports)):
        parser.error("listen ports must be unique")
    return args


async def copy_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(64 * 1024):
            writer.write(chunk)
            await writer.drain()
    finally:
        with contextlib.suppress(Exception):
            writer.write_eof()


async def proxy_connection(
    target: str,
    target_port: int,
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
) -> None:
    try:
        remote_reader, remote_writer = await asyncio.open_connection(target, target_port)
    except OSError:
        local_writer.close()
        await local_writer.wait_closed()
        return

    try:
        await asyncio.gather(
            copy_stream(local_reader, remote_writer),
            copy_stream(remote_reader, local_writer),
        )
    finally:
        remote_writer.close()
        local_writer.close()
        await asyncio.gather(
            remote_writer.wait_closed(),
            local_writer.wait_closed(),
            return_exceptions=True,
        )


async def run(args: argparse.Namespace) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected_signal, stop.set)

    servers = []
    for item in args.forward:
        server = await asyncio.start_server(
            lambda reader, writer, target_port=item.target_port: proxy_connection(
                args.target, target_port, reader, writer
            ),
            host="127.0.0.1",
            port=item.listen_port,
        )
        servers.append(server)

    print("remote DinD Kind loopback forwarder ready", flush=True)
    await stop.wait()
    for server in servers:
        server.close()
    await asyncio.gather(*(server.wait_closed() for server in servers))


if __name__ == "__main__":
    asyncio.run(run(parse_args()))
