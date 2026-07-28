# Third-party notices

## Limine boot protocol declarations and linker layout

Derived from the Limine Boot Protocol header and the Limine x86-64 C template.

- Project: Limine
- Sources:
  - `limine-protocol/include/limine.h`
  - `limine-c-template-x86-64/kernel/linker-scripts/x86_64.lds`
- Copyright: Mintsuki and contributors
- License: 0BSD

```text
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## RedoxFS

The filesystem core under `vendor/redoxfs` is adapted from RedoxFS commit `99bc185bf8ad8bd6f4d2562c424d800c2a3d310b`.

- Project: RedoxFS
- Source: https://github.com/redox-os/redoxfs
- Copyright: 2016 Jeremy Soller and contributors
- License: MIT
- Local adaptations: `no_std` import fixes, deterministic unencrypted formatting, and removal of userspace/encryption-only dependencies

The complete upstream license is retained at `vendor/redoxfs/LICENSE`.

## wasmi

- Project: wasmi
- Source: https://github.com/wasmi-labs/wasmi
- Version: 0.46.0
- Copyright: wasmi contributors
- License: MIT OR Apache-2.0
- Use: `no_std` WebAssembly interpreter for the ring-3 WASIp1 command runtime

## WebAssembly Binary Toolkit (WABT)

- Project: WABT
- Source: https://github.com/WebAssembly/wabt
- Release: https://github.com/WebAssembly/wabt/releases/tag/1.0.41
- Version: 1.0.41
- Copyright: WABT contributors
- License: Apache-2.0
- Use: official, unmodified WASI command modules bundled under `/system/bin`

The upstream license is retained at `vendor/wabt-1.0.41/LICENSE`.

## ProFont

- Project: ProFont for embedded-graphics
- Source: https://github.com/wezm/profont
- Copyright: 2018 Wes M
- License: MIT

## libyaff

- Project: libyaff, GinkgoOS fork
- Source: https://github.com/isaiahpettingill/libyaff
- Pinned revision: `4194ee0`
- Upstream source: https://github.com/mist64/libyaff
- License: MIT OR Apache-2.0
- Use: host-side YAFF parsing and conversion to the Ginkgo `.gkf` font format
- Local changes: `no_std + alloc` core support, handwritten label parsing, and `std`-gated filesystem helpers
