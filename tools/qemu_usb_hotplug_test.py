#!/usr/bin/env python3
"""QEMU/QMP smoke coverage for xHCI hubs, disconnect, and reconnect."""

import argparse
import json
import os
import re
import socket
import subprocess
import tempfile
import time


def wait_for_log(path: str, pattern: str, start: int, timeout: float) -> tuple[str, int]:
    deadline = time.monotonic() + timeout
    regex = re.compile(pattern, re.DOTALL)
    while time.monotonic() < deadline:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as stream:
                stream.seek(start)
                text = stream.read()
                end = stream.tell()
        except FileNotFoundError:
            text, end = "", start
        if regex.search(text):
            return text, end
        time.sleep(0.1)
    raise RuntimeError(f"serial log did not match {pattern!r}\n{text[-2000:]}")


def qmp_read(stream) -> dict:
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        message = json.loads(line)
        if "return" in message or "error" in message:
            return message


def qmp_command(stream, execute: str, arguments: dict | None = None) -> None:
    request = {"execute": execute}
    if arguments is not None:
        request["arguments"] = arguments
    stream.write((json.dumps(request) + "\n").encode())
    stream.flush()
    response = qmp_read(stream)
    if "error" in response:
        raise RuntimeError(f"QMP {execute} failed: {response['error']}")


def connect_qmp(port: int, timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=1)
            stream = connection.makefile("rwb", buffering=0)
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise RuntimeError("invalid QMP greeting")
            qmp_command(stream, "qmp_capabilities")
            return connection, stream
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("timed out connecting to QMP")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--ovmf", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--boot-root", required=True)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()

    port = free_port()
    with tempfile.TemporaryDirectory(prefix="ginkgo-usb-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
        command = [
            args.qemu,
            "-cpu", "max", "-m", "512M", "-M", "pc,i8042=off",
            "-display", "none", "-serial", f"file:{serial_log}",
            "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off",
            "-no-reboot", "-no-shutdown",
            "-drive", f"if=pflash,unit=0,format=raw,file={args.ovmf},readonly=on",
            "-drive", f"if=none,id=ginkgo-fs,format=raw,cache=writethrough,file={args.disk}",
            "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-fs",
            "-device", "qemu-xhci,id=xhci,msi=on,msix=off",
            "-device", "usb-hub,id=ginkgo-hub,bus=xhci.0,port=1",
            "-device", "usb-kbd,id=hotplug-kbd,bus=xhci.0,port=1.1",
            "-device", "usb-tablet,id=stable-tablet,bus=xhci.0,port=1.2",
            "-drive", f"if=none,id=ginkgo-boot,format=raw,file=fat:rw:{args.boot_root}",
            "-device", "ide-hd,drive=ginkgo-boot,bus=ide.1,unit=0", "-boot", "c",
        ]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL)
        connection = stream = None
        try:
            connection, stream = connect_qmp(port, args.timeout)
            text, cursor = wait_for_log(
                serial_log,
                r"USB topology: .*hub=true ports=8.*USB topology: .*route=00001.*USB HID: xHCI MSI enabled.*desktop-service: runtime online",
                0,
                args.timeout,
            )
            for _ in range(args.cycles):
                qmp_command(stream, "device_del", {"id": "hotplug-kbd"})
                text, cursor = wait_for_log(
                    serial_log,
                    r"USB hotplug: added=0 removed=1 live=1",
                    cursor,
                    args.timeout,
                )
                qmp_command(
                    stream,
                    "device_add",
                    {"driver": "usb-kbd", "id": "hotplug-kbd", "bus": "xhci.0", "port": "1.1"},
                )
                text, cursor = wait_for_log(
                    serial_log,
                    r"USB hotplug: added=1 removed=0 live=2",
                    cursor,
                    args.timeout,
                )
            with open(serial_log, "r", encoding="utf-8", errors="replace") as serial:
                complete = serial.read()
            interrupts = [int(value) for value in re.findall(r"interrupts=(\d+)", complete)]
            if len(interrupts) < args.cycles * 2 or interrupts[-1] <= interrupts[0]:
                raise RuntimeError(f"xHCI MSI did not progress across hotplug cycles\n{complete[-3000:]}")
            dropped = [int(value) for value in re.findall(r"dropped=(\d+)", complete)]
            if not dropped or any(dropped):
                raise RuntimeError(f"deferred xHCI events were dropped\n{complete[-3000:]}")
            frames = [int(value) for value in re.findall(r"frames=(\d+)", complete)]
            if not frames or len(set(frames)) != 1:
                raise RuntimeError(f"USB reconnect consumed unrecycled DMA frames: {frames}\n{complete[-3000:]}")
            if "ControllerError" in complete or "CPU exception" in complete:
                raise RuntimeError(f"fatal USB/kernel error in serial output\n{complete[-3000:]}")
            print(f"USB hub/hotplug smoke passed: {args.cycles} cycles, {max(interrupts)} interrupts")
        finally:
            if stream is not None:
                stream.close()
            if connection is not None:
                connection.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
