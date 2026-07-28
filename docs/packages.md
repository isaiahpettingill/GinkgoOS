# Application packages

GinkgoOS application installers use the deterministic GKP format. The terminal can create, inspect, install, update, and uninstall packages without a host-side packaging tool.

Shell command arguments are comma-separated. Quote display names and paths containing spaces.

## Wrap an executable

Create a command package directly from an ELF or WebAssembly file:

```text
package "hello.wasm", "hello.gkp", "tools.hello", "Hello", "1.0.0"
package "convert.elf", "convert.gkp", "tools.convert", "Convert", "1.0.0", "command"
```

The last argument is optional and defaults to `command`. Use `graphical` only for an ELF that creates its own windows:

```text
package "paint.elf", "paint.gkp", "tools.paint", "Paint", "1.0.0", "graphical"
```

The shell checks executable magic instead of trusting the filename. WebAssembly packages cannot be marked graphical until the Ginkgo WebAssembly window imports are available.

## Extract and edit a package

Extract a package into an editable directory:

```text
unpackage "hello.gkp", "hello-package"
```

The directory contains:

```text
hello-package/
  package.gkm
  executable.wasm
  assets/
    ...
```

`package.gkm` is a plain UTF-8 file:

```text
app_id=tools.hello
display_name=Hello
version=1.0.0
kind=command
format=wasm
executable=executable.wasm
```

Edit the manifest, replace the executable, or edit files under `assets/`. Asset paths are stored relative to `assets/`. Rebuild the package with:

```text
package "hello-package", "hello-1.1.0.gkp"
```

The packer recursively reads `assets/`, sorts paths for deterministic output, and rejects unsafe paths and duplicates. Executables may be up to 64 MiB, total asset data up to 8 MiB, and the complete GKP file up to 80 MiB.

## Install and uninstall

Install a new package or atomically update an existing app with the same app ID:

```text
install "hello.gkp"
```

List installed applications:

```text
installed
```

Uninstall an application:

```text
uninstall "tools.hello"
```

Uninstall removes the installed registry entry and immutable executable generation. It preserves application data. Use the existing `purge_app_data("tools.hello")` system function when the data must also be removed. System app IDs are protected and cannot be installed over or uninstalled.

## Trusting a large WASM application

Installed WASM applications use interpreter fuel and memory/table limits by default. After reviewing an installed executable, allow that exact generation to use the normal kernel process limits instead:

```text
trust "tools.python"
```

Restore interpreter limits for future launches with:

```text
untrust "tools.python"
```

Trust does not add filesystem, window, IPC, or other capabilities. It only removes the interpreter fuel and store memory/table ceilings; kernel scheduling and per-process memory limits still apply. Every install or update clears trust, so changed executable bytes must be reviewed and trusted again. Direct-path WASM files cannot be trusted because they have no installed identity or immutable registry generation.

## Running command and graphical apps

Run a command app in the current terminal and wait for its exit status:

```text
tools.hello "argument"
```

Run it without blocking the current terminal:

```text
launch "tools.hello", "argument"
```

`launch` opens a new terminal and asks that terminal to run the command. Graphical apps continue to launch directly through the desktop service.
