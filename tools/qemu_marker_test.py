#!/usr/bin/env python3
"""Boot a staged GinkgoOS tree and wait for one serial success marker."""

import argparse
import os
import subprocess
import tempfile
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--ovmf", required=True)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--boot-root", required=True)
    parser.add_argument("--success", required=True)
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="ginkgo-marker-") as temporary:
        serial_log = os.path.join(temporary, "serial.log")
        command = [
            args.qemu,
            "-cpu", "max", "-m", "512M", "-M", "pc,i8042=off",
            "-display", "none", "-serial", f"file:{serial_log}",
            "-no-reboot", "-no-shutdown",
            "-drive", f"if=pflash,unit=0,format=raw,file={args.ovmf},readonly=on",
            "-drive", f"if=none,id=ginkgo-fs,format=raw,cache=writethrough,file={args.disk}",
            "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-fs",
            "-drive", f"if=none,id=ginkgo-boot,format=raw,file=fat:rw:{args.boot_root}",
            "-device", "virtio-blk-pci,disable-modern=on,drive=ginkgo-boot",
        ]
        process = subprocess.Popen(command)
        deadline = time.monotonic() + args.timeout
        output = ""
        try:
            while time.monotonic() < deadline:
                try:
                    with open(serial_log, "r", encoding="utf-8", errors="replace") as stream:
                        output = stream.read()
                except FileNotFoundError:
                    pass
                if args.success in output:
                    print(args.success)
                    return
                if "ginkgo-thread-smoke:" in output and "failed" in output:
                    raise RuntimeError(output[-5000:])
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU exited with {process.returncode}\n{output[-5000:]}")
                time.sleep(0.1)
            raise RuntimeError(f"timed out waiting for {args.success!r}\n{output[-5000:]}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
