#!/usr/bin/env python3
"""Strict bounded QEMU harness for the generic request syscall smoke."""

import argparse
import os
import re
import subprocess
import tempfile
import time

FAIL_MARKER = "ginkgo-request-smoke: FAIL"
MARKERS = (
    "ginkgo-request-smoke: immediate PASS",
    "ginkgo-request-smoke: buffers PASS",
    "ginkgo-request-smoke: cancel PASS",
    "ginkgo-request-smoke: lifecycle PASS",
)
FINAL_MARKER = "ginkgo-request-smoke: PASS"
DIAGNOSTICS_PATTERN = re.compile(
    r"^ginkgo-request-smoke: diagnostics "
    r"queue=([0-9]+) peak=([0-9]+) active=([0-9]+) peak_active=([0-9]+) "
    r"completed=([0-9]+) "
    r"deadline_misses=([0-9]+) cancellations=([0-9]+) bytes=([0-9]+) "
    r"errors=([0-9]+) rejected=([0-9]+) dropped=([0-9]+)\r?$",
    re.MULTILINE,
)
DIAGNOSTIC_NAMES = (
    "queue",
    "peak",
    "active",
    "peak_active",
    "completed",
    "deadline_misses",
    "cancellations",
    "bytes",
    "errors",
    "rejected",
    "dropped",
)
FATAL_PATTERNS = (
    ("panic", re.compile(r"\bpanic(?:ked)?\b", re.IGNORECASE)),
    ("fatal", re.compile(r"\bfatal\b", re.IGNORECASE)),
    ("CPU exception", re.compile(r"\bCPU exception\b", re.IGNORECASE)),
    ("triple fault", re.compile(r"\btriple fault\b", re.IGNORECASE)),
)


def read_log(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except FileNotFoundError:
        return ""


def line_matches(log: str, marker: str) -> list[re.Match[str]]:
    return list(re.finditer(rf"^{re.escape(marker)}\r?$", log, re.MULTILINE))


def reject_failures(log: str) -> None:
    if FAIL_MARKER in log:
        raise RuntimeError(f"guest reported request-smoke failure\n{log[-10000:]}")
    for name, pattern in FATAL_PATTERNS:
        if pattern.search(log):
            raise RuntimeError(f"guest reported {name}\n{log[-10000:]}")


def parse_diagnostics(log: str) -> tuple[dict[str, int], int]:
    matches = list(DIAGNOSTICS_PATTERN.finditer(log))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one request diagnostics line, found {len(matches)}\n{log[-10000:]}"
        )
    match = matches[0]
    values = {name: int(value) for name, value in zip(DIAGNOSTIC_NAMES, match.groups())}
    return values, match.start()


def require_diagnostic_limits(values: dict[str, int], log: str) -> None:
    checks = (
        (values["queue"] == 0, "queue must drain to zero"),
        (values["active"] == 0, "active requests must drain to zero"),
        (values["peak"] >= 2, "peak queue depth must be at least 2"),
        (values["peak_active"] >= 64, "peak active requests must be at least 64"),
        (values["completed"] >= 74, "completed requests must be at least 74"),
        (values["deadline_misses"] >= 1, "deadline misses must be at least 1"),
        (values["cancellations"] >= 65, "cancellations must be at least 65"),
        (values["bytes"] >= 4609, "transferred bytes must be at least 4609"),
        (values["errors"] == 2, "failed request count must match reset/removal injection"),
        (values["rejected"] >= 1, "rejected requests must be at least 1"),
        (values["dropped"] == 0, "dropped completions must remain zero"),
    )
    for passed, message in checks:
        if not passed:
            raise RuntimeError(f"request diagnostic check failed: {message}\n{log[-10000:]}")


def validate_log(log: str) -> dict[str, int]:
    reject_failures(log)
    positions = []
    for marker in (*MARKERS, FINAL_MARKER):
        matches = line_matches(log, marker)
        if len(matches) != 1:
            raise RuntimeError(
                f"expected exactly one {marker!r}, found {len(matches)}\n{log[-10000:]}"
            )
        positions.append(matches[0].start())

    diagnostics, diagnostics_position = parse_diagnostics(log)
    expected_order = (*positions[:4], diagnostics_position, positions[4])
    if tuple(sorted(expected_order)) != expected_order:
        raise RuntimeError(f"request-smoke markers were out of order\n{log[-10000:]}")
    require_diagnostic_limits(diagnostics, log)
    return diagnostics


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
        "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-fs",
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
    with tempfile.TemporaryDirectory(prefix="ginkgo-request-") as temporary:
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
                final_count = len(line_matches(log, FINAL_MARKER))
                if final_count > 1:
                    raise RuntimeError(f"duplicate final PASS marker\n{log[-10000:]}")
                if final_count == 1:
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

    diagnostics = run(args)
    print(
        "request-smoke: diagnostics "
        + " ".join(f"{name}={diagnostics[name]}" for name in DIAGNOSTIC_NAMES)
    )
    print("request-smoke: PASS")


if __name__ == "__main__":
    main()
