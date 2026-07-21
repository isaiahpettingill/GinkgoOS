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

## ProFont

- Project: ProFont for embedded-graphics
- Source: https://github.com/wezm/profont
- Copyright: 2018 Wes M
- License: MIT
