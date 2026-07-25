#!/usr/bin/env python3
"""Strict bounded QEMU harness for the scheduler smoke workload."""

import argparse
import os
import re
import subprocess
import tempfile
import time

FAIL_MARKER = "ginkgo-scheduler-smoke: FAIL"
PHASE_MARKERS = (
    "ginkgo-scheduler-smoke: admission PASS",
    "ginkgo-scheduler-smoke: donation PASS",
)
SCHEDULER_MARKER = "ginkgo-scheduler-smoke: PASS"
FINAL_MARKER = "ginkgo-thread-smoke: PASS"
METRIC_NAMES = (
    "frames",
    "frame_misses",
    "frame_max_late_ns",
    "audio_periods",
    "audio_underruns",
    "audio_misses",
    "audio_max_late_ns",
    "input_events",
    "input_max_latency_ns",
    "background_bytes",
    "hog_ticks",
)
METRICS_PATTERN = re.compile(
    r"^ginkgo-scheduler-smoke: metrics "
    r"frames=([0-9]+) frame_misses=([0-9]+) frame_max_late_ns=([0-9]+) "
    r"audio_periods=([0-9]+) audio_underruns=([0-9]+) audio_misses=([0-9]+) "
    r"audio_max_late_ns=([0-9]+) input_events=([0-9]+) "
    r"input_max_latency_ns=([0-9]+) background_bytes=([0-9]+) hog_ticks=([0-9]+)\r?$",
    re.MULTILINE,
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
        raise RuntimeError(f"guest reported scheduler failure\n{log[-8000:]}")
    for name, pattern in FATAL_PATTERNS:
        if pattern.search(log):
            raise RuntimeError(f"guest reported {name}\n{log[-8000:]}")


def parse_metrics(log: str) -> tuple[dict[str, int], int]:
    matches = list(METRICS_PATTERN.finditer(log))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one scheduler metrics line, found {len(matches)}\n{log[-8000:]}"
        )
    match = matches[0]
    values = {name: int(value) for name, value in zip(METRIC_NAMES, match.groups())}
    return values, match.start()


def require_metric_limits(metrics: dict[str, int], log: str) -> None:
    checks = (
        (metrics["frames"] == 180, "frames must equal 180"),
        (metrics["frame_misses"] == 0, "frame_misses must equal 0"),
        (metrics["frame_max_late_ns"] <= 16_666_667, "frame_max_late_ns exceeds 16,666,667"),
        (metrics["audio_periods"] >= 300, "audio_periods must be at least 300"),
        (metrics["audio_underruns"] == 0, "audio_underruns must equal 0"),
        (metrics["audio_misses"] == 0, "audio_misses must equal 0"),
        (metrics["audio_max_late_ns"] <= 10_000_000, "audio_max_late_ns exceeds 10,000,000"),
        (metrics["input_events"] >= 100, "input_events must be at least 100"),
        (metrics["input_max_latency_ns"] <= 20_000_000, "input_max_latency_ns exceeds 20,000,000"),
        (metrics["background_bytes"] >= 1_048_576, "background_bytes must be at least 1,048,576"),
        (metrics["hog_ticks"] > 0, "hog_ticks must be greater than 0"),
    )
    for passed, message in checks:
        if not passed:
            raise RuntimeError(f"scheduler metric check failed: {message}\n{log[-8000:]}")


def validate_log(log: str) -> dict[str, int]:
    reject_failures(log)
    positions = []
    for marker in (*PHASE_MARKERS, SCHEDULER_MARKER, FINAL_MARKER):
        matches = line_matches(log, marker)
        if len(matches) != 1:
            raise RuntimeError(
                f"expected exactly one {marker!r}, found {len(matches)}\n{log[-8000:]}"
            )
        positions.append(matches[0].start())

    metrics, metrics_position = parse_metrics(log)
    expected_order = (*positions[:2], metrics_position, positions[2], positions[3])
    if tuple(sorted(expected_order)) != expected_order:
        raise RuntimeError(f"scheduler smoke markers were out of order\n{log[-8000:]}")

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
    with tempfile.TemporaryDirectory(prefix="ginkgo-scheduler-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
        process = subprocess.Popen(
            qemu_command(args, serial_log),
            stdin=subprocess.DEVNULL,
        )
        started = time.monotonic()
        try:
            deadline = started + args.timeout
            while time.monotonic() < deadline:
                log = read_log(serial_log)
                reject_failures(log)
                final_count = len(line_matches(log, FINAL_MARKER))
                if final_count > 1:
                    raise RuntimeError(f"duplicate final PASS marker\n{log[-8000:]}")
                if final_count == 1:
                    time.sleep(0.5)
                    settled = read_log(serial_log)
                    if process.poll() is not None:
                        raise RuntimeError(
                            f"QEMU exited early with status {process.returncode}\n{settled[-8000:]}"
                        )
                    return validate_log(settled)
                return_code = process.poll()
                if return_code is not None:
                    raise RuntimeError(
                        f"QEMU exited early with status {return_code}\n{log[-8000:]}"
                    )
                time.sleep(0.1)
            log = read_log(serial_log)
            raise RuntimeError(f"timed out after {args.timeout:.1f}s\n{log[-8000:]}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def print_summary(metrics: dict[str, int]) -> None:
    print(
        "scheduler-smoke: metrics "
        f"frames={metrics['frames']} frame_misses={metrics['frame_misses']} "
        f"frame_max_late_ns={metrics['frame_max_late_ns']} "
        f"audio_periods={metrics['audio_periods']} audio_underruns={metrics['audio_underruns']} "
        f"audio_misses={metrics['audio_misses']} audio_max_late_ns={metrics['audio_max_late_ns']} "
        f"input_events={metrics['input_events']} input_max_latency_ns={metrics['input_max_latency_ns']} "
        f"background_bytes={metrics['background_bytes']} hog_ticks={metrics['hog_ticks']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--ovmf", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--boot-root", required=True)
    parser.add_argument("--timeout", type=float, default=150)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    metrics = run(args)
    print_summary(metrics)
    print("scheduler-smoke: PASS")


if __name__ == "__main__":
    main()
