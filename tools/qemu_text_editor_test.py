#!/usr/bin/env python3
"""Boot one disk twice and verify the real text editor saves and reopens a document."""

import argparse
import os

import subprocess
import tempfile
import time

SAVED = "text-editor-smoke: saved"
REOPENED = "text-editor-smoke: reopened"
FAILURE = "text-editor-smoke: failure"


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
            raise RuntimeError(f"text editor smoke reported failure\n{serial[-4000:]}")
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
            "invalid text editor smoke markers: "
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


def boot(
    args: argparse.Namespace, boot_root: str, serial_log: str, expected: str
) -> str:
    command = [
        args.qemu,
        "-cpu", "max", "-m", "256M", "-M", "pc,i8042=off",
        "-display", "none", "-serial", f"file:{serial_log}",
        "-no-reboot", "-no-shutdown",
        "-drive", f"if=pflash,unit=0,format=raw,file={args.ovmf},readonly=on",
        "-drive", f"if=none,id=ginkgo-fs,format=raw,cache=writethrough,file={args.disk}",
        "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-fs",
        "-drive", f"if=none,id=ginkgo-boot,format=raw,file=fat:rw:{boot_root}",
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
    parser.add_argument("--disk", required=True)
    parser.add_argument("--save-root", required=True)
    parser.add_argument("--verify-root", required=True)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()



    with tempfile.TemporaryDirectory(prefix="ginkgo-text-editor-") as temporary:
        first_log = os.path.join(temporary, "save.log")
        second_log = os.path.join(temporary, "verify.log")
        first = boot(args, args.save_root, first_log, SAVED)
        assert_markers(first, SAVED, REOPENED)
        second = boot(args, args.verify_root, second_log, REOPENED)
        assert_markers(second, REOPENED, SAVED)

    print("text editor smoke passed: saved then reopened across reboot")


if __name__ == "__main__":
    main()
