#!/usr/bin/env python3
"""Boot one dedicated GPT disk twice and verify the filesystem hierarchy smoke."""

import argparse
import os
import shutil
import subprocess
import tempfile
import time

INITIALIZED = "filesystem-smoke: initialized"
PERSISTED = "filesystem-smoke: persisted"
FAILURE = "filesystem-smoke: failure"


def read_serial(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except FileNotFoundError:
        return ""


def wait_for_marker(path: str, expected: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    serial = ""
    while time.monotonic() < deadline:
        serial = read_serial(path)
        if FAILURE in serial:
            raise RuntimeError(f"kernel reported filesystem smoke failure\n{serial[-4000:]}")
        if expected in serial:
            return serial
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {expected!r}\n{serial[-4000:]}")


def assert_markers(serial: str, expected: str, unexpected: str) -> None:
    expected_count = serial.count(expected)
    unexpected_count = serial.count(unexpected)
    failure_count = serial.count(FAILURE)
    if expected_count != 1 or unexpected_count != 0 or failure_count != 0:
        raise RuntimeError(
            "invalid filesystem smoke markers: "
            f"{expected!r}={expected_count}, {unexpected!r}={unexpected_count}, "
            f"{FAILURE!r}={failure_count}\n{serial[-4000:]}"
        )


def terminate(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def boot(args: argparse.Namespace, serial_log: str, expected: str) -> str:
    command = [
        args.qemu,
        "-cpu", "max", "-m", "256M", "-M", "pc,i8042=off",
        "-display", "none", "-serial", f"file:{serial_log}",
        "-no-reboot", "-no-shutdown",
        "-drive", f"if=pflash,unit=0,format=raw,file={args.ovmf},readonly=on",
        "-drive", f"if=none,id=ginkgo-fs,format=raw,cache=writethrough,file={args.disk}",
        "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-fs",
        "-drive", f"if=none,id=ginkgo-boot,format=raw,file=fat:rw:{args.boot_root}",
        "-device", "ide-hd,drive=ginkgo-boot,bus=ide.1,unit=0", "-boot", "c",
    ]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL)
    try:
        return wait_for_marker(serial_log, expected, args.timeout)
    finally:
        terminate(process)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--ovmf", required=True)
    parser.add_argument("--source-disk", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--boot-root", required=True)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()

    source = os.path.abspath(args.source_disk)
    dedicated = os.path.abspath(args.disk)
    if source == dedicated:
        raise RuntimeError("filesystem smoke disk must be a dedicated copy")
    os.makedirs(os.path.dirname(dedicated), exist_ok=True)
    shutil.copyfile(source, dedicated)

    with tempfile.TemporaryDirectory(prefix="ginkgo-filesystem-") as temporary:
        first_log = os.path.join(temporary, "first-boot.log")
        second_log = os.path.join(temporary, "second-boot.log")
        first = boot(args, first_log, INITIALIZED)
        assert_markers(first, INITIALIZED, PERSISTED)
        second = boot(args, second_log, PERSISTED)
        assert_markers(second, PERSISTED, INITIALIZED)

    print("filesystem hierarchy smoke passed: initialized then persisted")


if __name__ == "__main__":
    main()
