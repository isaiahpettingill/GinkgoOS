#!/usr/bin/env python3
"""Sequential QEMU memory-policy matrix for low, normal, and high RAM."""

import argparse
import os
import re
import subprocess
import tempfile
import time

MIB = 1024 * 1024
GIB = 1024 * MIB
CASES = (
    ("low", "256M", 256 * MIB, False),
    ("normal", "512M", 512 * MIB, False),
    ("high", "5G", 5 * GIB, True),
)
FAIL_MARKER = "ginkgo-memory-policy-smoke: FAIL"
PHASES = {
    "Success": ("Exited", False),
    "Guard": ("PageFault", True),
    "ProtectFault": ("PageFault", True),
    "Oom": ("OutOfMemory", True),
    "Witness": ("Exited", False),
}
USER_MARKERS = (
    "ginkgo-memory-policy-user: success-stack-grown",
    "ginkgo-memory-policy-user: shared-mapped",
    "ginkgo-memory-policy-user: shared-unmapped",
    "ginkgo-memory-policy-user: anonymous-protected",
    "ginkgo-memory-policy-user: anonymous-unmapped",
    "ginkgo-memory-policy-user: guard-write-attempt",
    "ginkgo-memory-policy-user: protect-read-only",
    "ginkgo-memory-policy-user: oom-growth-attempt",
    "ginkgo-memory-policy-user: witness-stack-grown",
)
INSPECTION_PATTERNS = {
    "shared mapped": re.compile(
        r"^ginkgo-memory-policy-smoke: inspect shared mapped address=(0x[0-9a-f]+) frame=(0x[0-9a-f]+)\r?$",
        re.MULTILINE,
    ),
    "shared unmapped": re.compile(
        r"^ginkgo-memory-policy-smoke: inspect shared unmapped address=(0x[0-9a-f]+) frame=(0x[0-9a-f]+)\r?$",
        re.MULTILINE,
    ),
    "shared reclaimed": re.compile(
        r"^ginkgo-memory-policy-smoke: inspect shared reclaimed address=(0x[0-9a-f]+) frame=(0x[0-9a-f]+)\r?$",
        re.MULTILINE,
    ),
    "anonymous protected": re.compile(
        r"^ginkgo-memory-policy-smoke: inspect anonymous protected address=(0x[0-9a-f]+) frame=(0x[0-9a-f]+)\r?$",
        re.MULTILINE,
    ),
    "anonymous reclaimed": re.compile(
        r"^ginkgo-memory-policy-smoke: inspect anonymous reclaimed address=(0x[0-9a-f]+) frame=(0x[0-9a-f]+)\r?$",
        re.MULTILINE,
    ),
    "protect PTE read-only": re.compile(
        r"^ginkgo-memory-policy-smoke: inspect protect PTE read-only address=(0x[0-9a-f]+) frame=0x0\r?$",
        re.MULTILINE,
    ),
}
STATS_PATTERN = re.compile(
    r"^ginkgo-memory-policy-smoke: stats class=(low|normal|high) eligible_bytes=(\d+) "
    r"above_4g_frames=(\d+) highest_usable=(0x[0-9a-f]+) "
    r"highest_issued=(0x[0-9a-f]+) dma32=(\d+)\r?$",
    re.MULTILINE,
)
START_PATTERN = re.compile(
    r"^ginkgo-memory-policy-smoke: phase (Success|Guard|ProtectFault|Oom|Witness) "
    r"START pid=\d+ expected_address=(0x[0-9a-f]+)\r?$",
    re.MULTILINE,
)
PHASE_PASS_PATTERN = re.compile(
    r"^ginkgo-memory-policy-smoke: phase (Success|Guard|ProtectFault|Oom|Witness) "
    r"PASS reason=(Exited|PageFault|OutOfMemory) address=(none|0x[0-9a-f]+)\r?$",
    re.MULTILINE,
)


def read_log(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return stream.read()
    except FileNotFoundError:
        return ""


def reject_failures(log: str, case: str) -> None:
    lowered = log.lower()
    failures = (
        FAIL_MARKER,
        "CPU exception",
        "process reclaim invariant failed",
    )
    for failure in failures:
        if failure in log:
            raise RuntimeError(f"{case}: guest reported {failure!r}\n{log[-8000:]}")
    if any(text in lowered for text in ("outofframes", "out of frames", "out-of-frames")):
        raise RuntimeError(f"{case}: guest unexpectedly exhausted frames\n{log[-8000:]}")


def require_exact_once(log: str, marker: str, case: str) -> None:
    count = log.count(marker)
    if count != 1:
        raise RuntimeError(f"{case}: expected exactly one {marker!r}, found {count}\n{log[-8000:]}")


def validate_stats(log: str, case: str, configured: int, expect_high: bool) -> None:
    matches = STATS_PATTERN.findall(log)
    if len(matches) != 1:
        raise RuntimeError(f"{case}: expected exactly one RAM stats marker, found {len(matches)}\n{log[-8000:]}")
    ram_class, eligible_text, high_frames_text, highest_usable, highest_issued, dma_text = matches[0]
    eligible = int(eligible_text)
    high_frames = int(high_frames_text)
    if ram_class != case:
        raise RuntimeError(f"{case}: kernel classified RAM as {ram_class}\n{log[-8000:]}")
    hole_tolerance = 512 * MIB if expect_high else 192 * MIB
    if not (max(1, configured - hole_tolerance) <= eligible <= configured):
        raise RuntimeError(
            f"{case}: eligible RAM {eligible} is not within firmware-hole tolerance of configured {configured}\n{log[-8000:]}"
        )
    if expect_high:
        if high_frames == 0 or int(highest_usable, 16) < 4 * GIB or int(highest_issued, 16) < 4 * GIB:
            raise RuntimeError(f"{case}: high RAM was not usable and issued\n{log[-8000:]}")
    elif high_frames != 0 or int(highest_usable, 16) >= 4 * GIB or int(highest_issued, 16) >= 4 * GIB:
        raise RuntimeError(f"{case}: low RAM profile reported a high frame\n{log[-8000:]}")
    if int(dma_text) < 1:
        raise RuntimeError(f"{case}: DMA32 allocation was not exercised\n{log[-8000:]}")


def validate_phases(log: str, case: str) -> None:
    starts = START_PATTERN.findall(log)
    passes = PHASE_PASS_PATTERN.findall(log)
    if len(starts) != len(PHASES) or len(passes) != len(PHASES):
        raise RuntimeError(
            f"{case}: expected {len(PHASES)} phase starts and passes, found {len(starts)} and {len(passes)}\n{log[-8000:]}"
        )
    start_by_phase = {}
    for phase, address in starts:
        if phase in start_by_phase:
            raise RuntimeError(f"{case}: duplicate {phase} START\n{log[-8000:]}")
        start_by_phase[phase] = address
    pass_by_phase = {}
    for phase, reason, address in passes:
        if phase in pass_by_phase:
            raise RuntimeError(f"{case}: duplicate {phase} PASS\n{log[-8000:]}")
        pass_by_phase[phase] = (reason, address)
    for phase, (expected_reason, has_address) in PHASES.items():
        if phase not in start_by_phase or phase not in pass_by_phase:
            raise RuntimeError(f"{case}: missing phase {phase}\n{log[-8000:]}")
        reason, address = pass_by_phase[phase]
        expected_address = start_by_phase[phase]
        if reason != expected_reason:
            raise RuntimeError(f"{case}: {phase} reason was {reason}, expected {expected_reason}\n{log[-8000:]}")
        if has_address and (address == "none" or address != expected_address):
            raise RuntimeError(f"{case}: {phase} address {address} did not match {expected_address}\n{log[-8000:]}")
        if not has_address and address != "none":
            raise RuntimeError(f"{case}: {phase} unexpectedly reported address {address}\n{log[-8000:]}")


def validate_operations(log: str, case: str, expect_high: bool) -> None:
    for marker in USER_MARKERS:
        require_exact_once(log, marker, case)
    inspections = {}
    for name, pattern in INSPECTION_PATTERNS.items():
        matches = pattern.findall(log)
        if len(matches) != 1:
            raise RuntimeError(f"{case}: expected exactly one {name} inspection, found {len(matches)}\n{log[-8000:]}")
        inspections[name] = matches[0]

    shared_address, shared_frame = inspections["shared mapped"]
    if inspections["shared unmapped"] != (shared_address, shared_frame):
        raise RuntimeError(f"{case}: shared unmap changed frame identity\n{log[-8000:]}")
    if inspections["shared reclaimed"] != (shared_address, shared_frame):
        raise RuntimeError(f"{case}: shared reclaim changed frame identity\n{log[-8000:]}")
    anonymous_address, anonymous_frame = inspections["anonymous protected"]
    if inspections["anonymous reclaimed"] != (anonymous_address, anonymous_frame):
        raise RuntimeError(f"{case}: anonymous reclaim changed frame identity\n{log[-8000:]}")
    if expect_high and (int(shared_frame, 16) < 4 * GIB or int(anonymous_frame, 16) < 4 * GIB):
        raise RuntimeError(f"{case}: shared or anonymous backing was below 4GiB\n{log[-8000:]}")

    required_order = (
        "ginkgo-memory-policy-user: shared-mapped",
        "inspect shared mapped",
        "ginkgo-memory-policy-user: shared-unmapped",
        "inspect shared unmapped",
        "inspect shared reclaimed",
        "ginkgo-memory-policy-user: anonymous-protected",
        "inspect anonymous protected",
        "ginkgo-memory-policy-user: anonymous-unmapped",
        "inspect anonymous reclaimed",
        "phase Success PASS",
    )
    positions = [log.find(token) for token in required_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise RuntimeError(f"{case}: map/unmap/reclaim markers were out of order\n{log[-8000:]}")


def validate_global_order(log: str, case: str) -> None:
    required_order = (
        "phase Success START",
        "ginkgo-memory-policy-user: success-stack-grown",
        "ginkgo-memory-policy-user: shared-mapped",
        "inspect shared mapped",
        "ginkgo-memory-policy-user: shared-unmapped",
        "inspect shared unmapped",
        "inspect shared reclaimed",
        "ginkgo-memory-policy-user: anonymous-protected",
        "inspect anonymous protected",
        "ginkgo-memory-policy-user: anonymous-unmapped",
        "inspect anonymous reclaimed",
        "phase Success PASS",
        "phase Guard START",
        "ginkgo-memory-policy-user: guard-write-attempt",
        "phase Guard PASS",
        "phase ProtectFault START",
        "ginkgo-memory-policy-user: protect-read-only",
        "inspect protect PTE read-only",
        "phase ProtectFault PASS",
        "phase Oom START",
        "ginkgo-memory-policy-user: oom-growth-attempt",
        "phase Oom PASS",
        "phase Witness START",
        "ginkgo-memory-policy-user: witness-stack-grown",
        "phase Witness PASS",
        f"ginkgo-memory-policy-smoke: {case} PASS",
    )
    positions = [log.find(token) for token in required_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise RuntimeError(f"{case}: global phase transcript was incomplete or out of order\n{log[-8000:]}")


def validate_log(log: str, case: str, configured: int, expect_high: bool) -> None:
    reject_failures(log, case)
    require_exact_once(log, f"ginkgo-memory-policy-smoke: {case} PASS", case)
    validate_stats(log, case, configured, expect_high)
    validate_phases(log, case)
    validate_operations(log, case, expect_high)
    validate_global_order(log, case)


def run_case(
    args: argparse.Namespace,
    case: str,
    memory: str,
    configured: int,
    expect_high: bool,
) -> float:
    with tempfile.TemporaryDirectory(prefix=f"ginkgo-memory-policy-{case}-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
        command = [
            args.qemu,
            "-accel", "tcg",
            "-cpu", "max",
            "-m", memory,
            "-M", "pc,i8042=off",
            "-display", "none",
            "-serial", f"file:{serial_log}",
            "-monitor", "none",
            "-no-reboot",
            "-no-shutdown",
            "-drive", f"if=pflash,unit=0,format=raw,file={args.ovmf},readonly=on",
            "-drive", f"if=none,id=ginkgo-fs,format=raw,cache=writethrough,file={args.disk}",
            "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-fs",
            "-drive", f"if=none,id=ginkgo-boot,format=raw,file=fat:rw:{args.boot_root}",
            "-device", "ide-hd,drive=ginkgo-boot,bus=ide.1,unit=0",
            "-boot", "c",
        ]
        started = time.monotonic()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL)
        final_marker = f"ginkgo-memory-policy-smoke: {case} PASS"
        try:
            deadline = started + args.timeout
            while time.monotonic() < deadline:
                log = read_log(serial_log)
                reject_failures(log, case)
                if log.count(final_marker) > 1:
                    raise RuntimeError(f"{case}: duplicate final PASS marker\n{log[-8000:]}")
                if final_marker in log:
                    time.sleep(0.25)
                    settled = read_log(serial_log)
                    validate_log(settled, case, configured, expect_high)
                    return time.monotonic() - started
                return_code = process.poll()
                if return_code is not None:
                    raise RuntimeError(
                        f"{case}: QEMU exited early with status {return_code}\n{log[-8000:]}"
                    )
                time.sleep(0.1)
            log = read_log(serial_log)
            raise RuntimeError(f"{case}: timed out after {args.timeout:.1f}s\n{log[-8000:]}")
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
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    args = parser.parse_args()

    selected = [case for case in CASES if args.case is None or case[0] == args.case]
    total_started = time.monotonic()
    for case, memory, configured, expect_high in selected:
        elapsed = run_case(args, case, memory, configured, expect_high)
        print(f"memory-policy-smoke: {case} PASS ({elapsed:.2f}s)", flush=True)
    print(f"memory-policy-smoke: matrix PASS ({time.monotonic() - total_started:.2f}s)")


if __name__ == "__main__":
    main()
