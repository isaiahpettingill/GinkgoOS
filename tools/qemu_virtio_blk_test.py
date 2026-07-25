#!/usr/bin/env python3
"""Strict bounded QEMU harness for the virtio-blk smoke workload."""

import argparse
import os
import re
import subprocess
import tempfile
import time

PASS_PREFIX = "virtio-blk-smoke: PASS"
METRIC_NAMES = (
    "msix",
    "interrupts",
    "queue_hwm",
    "driver_hwm",
    "bytes",
    "errors",
    "live",
    "queued",
    "in_flight",
)
PASS_LINE_PATTERN = re.compile(
    r"^virtio-blk-smoke: PASS(?: .*)?\r?$",
    re.MULTILINE,
)
PASS_PATTERN = re.compile(
    r"^virtio-blk-smoke: PASS "
    r"msix=([0-9]+) interrupts=([0-9]+) "
    r"queue_hwm=([0-9]+) driver_hwm=([0-9]+) bytes=([0-9]+) "
    r"errors=([0-9]+) live=([0-9]+) queued=([0-9]+) in_flight=([0-9]+)\r?$",
    re.MULTILINE,
)
FATAL_PATTERNS = (
    (
        "failure marker",
        re.compile(r"^.*(?:smoke|-smoke): (?:FAIL|failure|failed)\b", re.IGNORECASE | re.MULTILINE),
    ),
    ("CPU exception", re.compile(r"\bCPU exception\b", re.IGNORECASE)),
    ("panic", re.compile(r"\bpanic(?:ked)?\b", re.IGNORECASE)),
    ("fatal", re.compile(r"\bfatal\b", re.IGNORECASE)),
    ("triple fault", re.compile(r"\btriple fault\b", re.IGNORECASE)),
)


def read_log(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except FileNotFoundError:
        return ""


def reject_failures(log: str) -> None:
    for name, pattern in FATAL_PATTERNS:
        if pattern.search(log):
            raise RuntimeError(f"guest reported {name}\n{log[-10000:]}")


def parse_pass(log: str) -> dict[str, int]:
    pass_lines = list(PASS_LINE_PATTERN.finditer(log))
    if len(pass_lines) != 1:
        raise RuntimeError(
            f"expected exactly one {PASS_PREFIX!r} line, found {len(pass_lines)}\n{log[-10000:]}"
        )

    matches = list(PASS_PATTERN.finditer(log))
    if len(matches) != 1:
        raise RuntimeError(f"malformed virtio-blk PASS marker\n{log[-10000:]}")
    return {name: int(value) for name, value in zip(METRIC_NAMES, matches[0].groups())}


def require_metric_limits(metrics: dict[str, int], log: str) -> None:
    checks = (
        (metrics["msix"] == 1, "msix must equal 1"),
        (metrics["interrupts"] > 0, "interrupts must be greater than 0"),
        (metrics["queue_hwm"] > 1, "queue_hwm must be greater than 1"),
        (metrics["driver_hwm"] > 1, "driver_hwm must be greater than 1"),
        (metrics["bytes"] >= 65_536, "bytes must be at least 65,536"),
        (metrics["errors"] == 0, "errors must equal 0"),
        (metrics["live"] == 0, "live requests must drain to zero"),
        (metrics["queued"] == 0, "queued requests must drain to zero"),
        (metrics["in_flight"] == 0, "in-flight requests must drain to zero"),
    )
    for passed, message in checks:
        if not passed:
            raise RuntimeError(f"virtio-blk metric check failed: {message}\n{log[-10000:]}")


def validate_log(log: str) -> dict[str, int]:
    reject_failures(log)
    metrics = parse_pass(log)
    require_metric_limits(metrics, log)
    return metrics


def qemu_command(args: argparse.Namespace, serial_log: str) -> list[str]:
    return [
        args.qemu,
        "-accel", "tcg",
        "-cpu", "max",
        "-m", "512M",
        "-M", "pc,i8042=off",
        "-display", "none",
        "-serial", f"file:{serial_log}",
        "-monitor", "none",
        "-no-reboot",
        "-no-shutdown",
        "-drive", f"if=pflash,unit=0,format=raw,file={args.ovmf},readonly=on",
        "-drive", f"if=none,id=ginkgo-fs,format=raw,cache=writethrough,file={args.disk}",
        "-device", "virtio-blk-pci,disable-modern=on,vectors=2,drive=ginkgo-fs",
        "-device", "qemu-xhci,id=xhci,msi=on,msix=off",
        "-device", "usb-kbd,bus=xhci.0,port=1",
        "-audiodev", "none,id=ginkgo-audio",
        "-device", "ich9-intel-hda",
        "-device", "hda-output,audiodev=ginkgo-audio",
        "-drive", f"if=none,id=ginkgo-boot,format=raw,file=fat:rw:{args.boot_root}",
        "-device", "ide-hd,drive=ginkgo-boot,bus=ide.1,unit=0",
        "-boot", "c",
    ]


def run(args: argparse.Namespace) -> dict[str, int]:
    with tempfile.TemporaryDirectory(prefix="ginkgo-virtio-blk-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
        process = subprocess.Popen(
            qemu_command(args, serial_log),
            stdin=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                log = read_log(serial_log)
                reject_failures(log)
                pass_count = len(PASS_LINE_PATTERN.findall(log))
                if pass_count > 1:
                    raise RuntimeError(f"duplicate virtio-blk PASS marker\n{log[-10000:]}")
                if pass_count == 1:
                    time.sleep(0.5)
                    settled = read_log(serial_log)
                    if process.poll() is not None:
                        raise RuntimeError(
                            f"QEMU exited early with status {process.returncode}\n{settled[-10000:]}"
                        )
                    return validate_log(settled)
                return_code = process.poll()
                if return_code is not None:
                    raise RuntimeError(
                        f"QEMU exited early with status {return_code}\n{log[-10000:]}"
                    )
                time.sleep(0.1)
            log = read_log(serial_log)
            raise RuntimeError(f"timed out after {args.timeout:.1f}s\n{log[-10000:]}")
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
    parser.add_argument("--disk", required=True)
    parser.add_argument("--boot-root", required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    metrics = run(args)
    print(
        "virtio-blk-smoke: metrics "
        + " ".join(f"{name}={metrics[name]}" for name in METRIC_NAMES)
    )
    print("virtio-blk-smoke: PASS")


if __name__ == "__main__":
    main()
