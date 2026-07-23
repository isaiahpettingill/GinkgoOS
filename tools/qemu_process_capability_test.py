#!/usr/bin/env python3
"""Bounded headless QEMU smoke for userspace process capabilities."""

import argparse
import os
import subprocess
import tempfile
import time

PASS_MARKER = "ginkgo-process-capability-smoke: PASS"
FAIL_MARKER = "ginkgo-process-capability-smoke: FAIL"


def wait_for_result(path: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as stream:
                last = stream.read()
        except FileNotFoundError:
            time.sleep(0.1)
            continue

        if FAIL_MARKER in last:
            raise RuntimeError(f"userspace smoke reported failure\n{last[-4000:]}")
        for failure in ("process reclaim invariant failed", "OutOfFrames", "CPU exception"):
            if failure in last:
                raise RuntimeError(f"kernel reported {failure!r}\n{last[-4000:]}")
        count = last.count(PASS_MARKER)
        if count > 1:
            raise RuntimeError(f"duplicate pass marker ({count})\n{last[-4000:]}")
        if count == 1:
            time.sleep(0.25)
            with open(path, "r", encoding="utf-8", errors="replace") as stream:
                settled = stream.read()
            if settled.count(PASS_MARKER) != 1:
                raise RuntimeError(f"pass marker was not unique\n{settled[-4000:]}")
            if FAIL_MARKER in settled:
                raise RuntimeError(f"failure followed pass marker\n{settled[-4000:]}")
            return PASS_MARKER
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for process capability smoke\n{last[-4000:]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--ovmf", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--boot-root", required=True)
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="ginkgo-process-capability-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
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
            print(wait_for_result(serial_log, args.timeout))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
