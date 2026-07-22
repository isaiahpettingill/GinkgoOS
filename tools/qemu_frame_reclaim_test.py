#!/usr/bin/env python3
"""Headless QEMU stress test for process and frame reclamation."""

import argparse
import os
import re
import subprocess
import tempfile
import time


def wait_for_result(path: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    success = re.compile(
        r"frame-reclaim stress passed cycles=(\d+) reuse_checks=(\d+) baseline_live=(\d+) final_live=(\d+) reusable=(\d+) baseline_shared=(\d+) final_shared=(\d+)"
    )
    failures = (
        "frame-reclaim stress leak",
        "frame-reclaim stress fresh allocation",
        "frame-reclaim stress unexpected state",
        "frame-reclaim stress respawn failed",
        "process reclaim invariant failed",
        "OutOfFrames",
        "CPU exception",
    )
    while time.monotonic() < deadline:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as stream:
                last = stream.read()
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        for failure in failures:
            if failure in last:
                raise RuntimeError(f"kernel reported {failure!r}\n{last[-4000:]}")
        match = success.search(last)
        if match:
            (
                cycles,
                reuse_checks,
                baseline,
                final,
                reusable,
                baseline_shared,
                final_shared,
            ) = map(int, match.groups())
            if (
                cycles != 512
                or reuse_checks != 511
                or baseline != final
                or reusable == 0
                or baseline_shared != final_shared
            ):
                raise RuntimeError(f"invalid stress result: {match.group(0)}")
            return match.group(0)
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for frame reclaim stress\n{last[-4000:]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--ovmf", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--boot-root", required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="ginkgo-reclaim-") as temporary:
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
            result = wait_for_result(serial_log, args.timeout)
            print(result)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
