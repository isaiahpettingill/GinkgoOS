#!/usr/bin/env python3
"""Bounded QEMU smoke for orderly ACPI power-off, reboot, and cancellation."""

import argparse
import os
import subprocess
import tempfile
import time

FATAL_MARKERS = (
    "power-smoke: persistence verification failed",
    "power-smoke: sync staging failed",
    "power: synchronization failed",
    "power: ACPI transition failed",
    "CPU exception",
)


def read_log(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except FileNotFoundError:
        return ""


def command(args, root: str, disk: str, serial_log: str, no_reboot: bool) -> list[str]:
    result = [
        args.qemu,
        "-cpu", "max", "-m", "256M", "-M", "pc,i8042=off",
        "-display", "none", "-serial", f"file:{serial_log}",
    ]
    if no_reboot:
        result.append("-no-reboot")
    result.extend([
        "-drive", f"if=pflash,unit=0,format=raw,file={args.ovmf},readonly=on",
        "-drive", f"if=none,id=ginkgo-fs,format=raw,cache=writethrough,file={disk}",
        "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-fs",
        "-drive", f"if=none,id=ginkgo-boot,format=raw,file=fat:rw:{root}",
        "-device", "ide-hd,drive=ginkgo-boot,bus=ide.1,unit=0", "-boot", "c",
    ])
    return result


def assert_log(log: str, marker: str) -> None:
    for fatal in FATAL_MARKERS:
        if fatal in log:
            raise RuntimeError(f"kernel reported {fatal!r}\n{log[-5000:]}")
    if marker not in log:
        raise RuntimeError(f"missing marker {marker!r}\n{log[-5000:]}")
    if "acpi: reset and S5 power-off ready" not in log:
        raise RuntimeError(f"ACPI power discovery did not succeed\n{log[-5000:]}")


def run_poweroff(args, root: str, disk: str, marker: str, timeout: float) -> None:
    with tempfile.TemporaryDirectory(prefix="ginkgo-poweroff-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
        process = subprocess.Popen(
            command(args, root, disk, serial_log, no_reboot=True),
            stdin=subprocess.DEVNULL,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            process.terminate()
            process.wait(timeout=5)
            log = read_log(serial_log)
            raise RuntimeError(f"QEMU did not power off within {timeout}s\n{log[-5000:]}") from error
        log = read_log(serial_log)
        if process.returncode != 0:
            raise RuntimeError(f"QEMU power-off exited {process.returncode}\n{log[-5000:]}")
        assert_log(log, marker)


def run_reboot(args, root: str, disk: str, timeout: float) -> None:
    with tempfile.TemporaryDirectory(prefix="ginkgo-reboot-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
        process = subprocess.Popen(
            command(args, root, disk, serial_log, no_reboot=False),
            stdin=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                log = read_log(serial_log)
                for fatal in FATAL_MARKERS:
                    if fatal in log:
                        raise RuntimeError(f"kernel reported {fatal!r}\n{log[-5000:]}")
                if "power-smoke: reboot observed" in log:
                    if log.count("acpi: reset and S5 power-off ready") < 2:
                        raise RuntimeError(f"reboot marker appeared without two ACPI boots\n{log[-5000:]}")
                    return
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU exited before reboot was observed\n{log[-5000:]}")
                time.sleep(0.1)
            raise RuntimeError(f"timed out waiting for reboot\n{read_log(serial_log)[-5000:]}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--ovmf", required=True)
    parser.add_argument("--sync-root", required=True)
    parser.add_argument("--verify-root", required=True)
    parser.add_argument("--cancel-root", required=True)
    parser.add_argument("--reboot-root", required=True)
    parser.add_argument("--persist-disk", required=True)
    parser.add_argument("--cancel-disk", required=True)
    parser.add_argument("--reboot-disk", required=True)
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()

    run_poweroff(
        args,
        args.sync_root,
        args.persist_disk,
        "power-smoke: sync-before-poweroff staged",
        args.timeout,
    )
    run_poweroff(
        args,
        args.verify_root,
        args.persist_disk,
        "power-smoke: persisted after poweroff",
        args.timeout,
    )
    run_poweroff(
        args,
        args.cancel_root,
        args.cancel_disk,
        "power-smoke: cancellation passed",
        args.timeout,
    )
    run_reboot(args, args.reboot_root, args.reboot_disk, args.timeout)
    print("ginkgo-power-smoke: PASS")


if __name__ == "__main__":
    main()
