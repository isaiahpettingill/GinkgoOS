# GinkgoOS userspace workspace

This is the production, nested `x86_64-unknown-none` workspace. It is intentionally independent of the kernel's root Cargo workspace.

## Packages

- `ginkgo-runtime`: shared `no_std` syscall-backed growable Talc heap, panic/exit handling, `_start` entry macro, linker script, and build-script helper.
- `ginkgo-desktop-service`: production window-policy service using `ginkgo_desktop::Desktop`, the broker runtime protocol, per-app channels, and protected two-buffer surface pools.
- `ginkgo-minimal-client`: production syscall-backed `WindowTransport`/`WindowClient` demo with a centered “Hello World” surface and `F11` fullscreen toggling.
- `ginkgo-help`: unprivileged desktop-controls guide launched from the registry or the system tray Help button.
- `ginkgo-file-navigator`: keyboard-controlled `/user` workspace browser; Up/Down selects, Enter enters a directory or securely launches the text editor for a file, Backspace returns, and Delete removes entries.
- `ginkgo-text-editor`: persistent UTF-8 editor scoped to `/user`, with open/save/save-as, selection, clipboard, undo/redo, and startup document requests from the file navigator.
- `ginkgo-terminal`: terminal emulator and bounded Ginkgo shell. Pest parses the language before a register-machine bytecode VM runs it. Scripts can perform root file I/O, launch and inspect headless ELF jobs, manage bounded GKP installations, include another script once, and request registry-governed graphical launches.
- `validator`: host-only copy of the existing validation harness pattern which imports the kernel ELF parser directly.

## Build and validate

Normal root Makefile builds compile the production ELFs before the kernel and pass their paths into the kernel build for embedding as `/system/desktop.elf`, `/system/help.elf`, `/system/file-navigator.elf`, `/system/text-editor.elf`, `/system/minimal-client.elf`, and `/system/terminal.elf` alongside `/system/programs.gkr`.

```sh
cargo build --release --target x86_64-unknown-none -p ginkgo-desktop-service -p ginkgo-help -p ginkgo-file-navigator -p ginkgo-text-editor -p ginkgo-minimal-client -p ginkgo-terminal
cargo run --manifest-path validator/Cargo.toml --target x86_64-pc-windows-msvc -- \
  target/x86_64-unknown-none/release/ginkgo-desktop-service \
  target/x86_64-unknown-none/release/ginkgo-file-navigator \
  target/x86_64-unknown-none/release/ginkgo-text-editor \
  target/x86_64-unknown-none/release/ginkgo-minimal-client \
  target/x86_64-unknown-none/release/ginkgo-terminal
```

The terminal itself cannot use Rust's host test harness because it is a `no_std`, `no_main` GinkgoOS binary tied to the userspace syscall ABI. Pure GKP parser, bounds, unsafe-path, canonical registry, atomic mutation, and protected-ID behavior is covered by the `ginkgo-app-package` host tests:

```sh
cargo test -p ginkgo-app-package --features host --target x86_64-pc-windows-msvc
```

Artifacts:

- `target/x86_64-unknown-none/release/ginkgo-desktop-service`
- `target/x86_64-unknown-none/release/ginkgo-minimal-client`
- `target/x86_64-unknown-none/release/ginkgo-help`
- `target/x86_64-unknown-none/release/ginkgo-file-navigator`
- `target/x86_64-unknown-none/release/ginkgo-text-editor`
- `target/x86_64-unknown-none/release/ginkgo-terminal`

## Runtime integration

The kernel boots `ginkgo-desktop-service` with only one bootstrap channel and the output dimensions. It creates the persistent `/user` workspace idempotently and launches ordinary registered applications with a non-transferable, non-duplicable `READ | WRITE` directory capability rooted there; paths cannot escape to `/system`, `/applications`, or `/appdata`. The trusted terminal is the exception: package management and explicit executable launch require its existing root `READ | WRITE | EXECUTE` authority, but its logical starting directory is `/user`. The service and kernel broker provision protected shared-memory surfaces and client/manager capabilities. The boot registry exposes `Files`, `Text Editor`, `Terminal`, and `Ginkgo Demo` while keeping the desktop service hidden. General launch authority remains terminal-only; the file navigator has a separate narrow permission that can launch only the trusted text editor for a selected document.

## Terminal shell

The terminal uses the Ginkgo shell language. Pest parses each input or loaded file into an AST, which is compiled to register-machine bytecode before execution. Variables, aliases, functions, and included-file state persist for the life of the terminal. Execution is bounded to 100,000 bytecode instructions, 32 nested calls, 4,096 list values, and 64 KiB of source or string data. Left and Right move the input cursor so text can be inserted or removed inside the pending command; Up and Down browse command history.

Bare commands take comma-separated values:

```gsh
ls
ls /system
cd documents
cat "notes, with commas.txt"
cp notes.txt, backup.txt
rm archive.txt, old.txt
print "hello from Ginkgo"
```

Values include strings, signed integers, booleans, variables, and lists. Unquoted glob expressions expand through the terminal's logical current directory. A glob used as a command argument is spliced into the command's argument list; a glob assigned to a variable or used by `for` is a list.

```gsh
$name = "Ginkgo"
$files = **/*.ts
print @["hello", $name, 10, true]
for $file in *.txt do
  print $file
end
```

The language supports `not`, `and`, `or`, `==`, `<>`, `>`, `<`, `<=`, and `>=`, with short-circuit boolean evaluation. It also supports Ruby-like functions and loops:

```gsh
def greet($name)
  print $name
end

greet "world"

while $ready do
  print "ready"
end

until $ready do
  print "waiting"
end

repeat 5 times
  print "again"
end

do
  print "once"
while false
```

`include "path/to/file.gsh"` reads a script relative to the logical current directory and evaluates it in the same interpreter. Each include path is evaluated once. `run "path/to/file.gsh"` evaluates the file every time. Include and run cycles are rejected. `#pragma once` is accepted as a comment because include-once behavior is always enabled.

Aliases use `alias short = target`. Dispatch follows this order:

1. An absolute path such as `/system/tool.elf`.
2. A user alias or user function.
3. An installed package or trusted program-registry entry.
4. A builtin.

`!app-name` always launches a registered application. `%builtin` always invokes a builtin, even when a function or alias has the same name. App IDs and executable basenames such as `text-editor` and `text-editor.elf` resolve through the program registry. A normal graphical app command opens a new window and holds the prompt until the app exits. `launch app-name` starts it without holding the prompt. Installed command apps and absolute ELF paths follow the same foreground/background rule.

Built-in canonical names and aliases are:

| Canonical name | Aliases | Result |
| --- | --- | --- |
| `list_files` | `ls`, `dir` | Structured directory-entry list |
| `change_directory` | `cd`, `chdir` | Changes the terminal's capability-rooted logical directory |
| `current_directory` | `pwd`, `cwd` | Logical directory beginning at `/` |
| `copy` | `cp` | Copies one file without escaping the filesystem capability |
| `move` | `mv`, `ren`, `rename` | Moves or renames without replacing an existing destination |
| `remove` | `rm`, `del`, `delete` | Removes one or more files |
| `make_directory` | `mkdir`, `md` | Creates one or more directories |
| `remove_directory` | `rmdir`, `rd` | Removes one or more empty directories |
| `show_file` | `cat`, `type` | Returns file text |
| `edit` | — | Opens a `/user` file in a new text editor window and waits |
| `launch` | — | Starts a registered app or ELF without waiting |
| `exit` | `quit` | Closes the terminal |
| `clear_terminal` | `clear`, `cls` | Clears terminal scrollback |
| `show_processes` | `ps`, `tasks` | Structured terminal-owned job list |
| `terminate_process` | `kill`, `stop` | Terminates a terminal-owned job ID |
| `print` | `output` | Prints one value |
| `help` | — | Shows command and syntax help |

Low-level host operations use the same bare-command syntax. For example:

```gsh
write_file "documents/notes.txt", "persistent text"
append_file "documents/notes.txt", "\nmore"
$contents = read_file "documents/notes.txt"
$metadata = metadata "documents/notes.txt"
rename_path "documents/notes.txt", "documents/archive.txt", false
sync_filesystem

$job = spawn_elf "hello.elf", @["--verbose"]
process_status $job
wait_process $job
close_process $job

install_package "paint.gkp"
$installed = list_installed
$job = spawn_installed "tools.paint", @["document.gkg"]
run "/user/scripts/setup.gsh"
edit "documents/notes.txt"
text-editor
launch minimal-client
```

Directory-entry lists and terminal-job lists are rendered as compact tables. Other lists render one value per line.

### Filesystem functions

All terminal filesystem access remains beneath its explicit trusted filesystem-root capability. The shell starts in `/user`; shell commands, includes, globs, and executable paths resolve from that logical directory. A leading `/` addresses the capability root, and normalization rejects attempts to ascend above it. Low-level filesystem builtins remain explicit capability-root-relative APIs. The kernel has no ambient current-working-directory state: ordinary graphical processes instead receive `/user` itself as their scoped filesystem capability.

- `mkdir path` creates one directory; parent directories must already exist.
- `rmdir path` removes an empty directory.
- `rename_path source, destination, replace` atomically renames or moves a file or directory beneath the same root.
- `sync_filesystem` flushes pending filesystem data and metadata.
- `filesystem_info` returns capacity and limit fields.
- `metadata path` returns kind, stable identity, numeric mode, size, and timestamps.
- `list_directory path` returns up to 256 rich entry maps.

Filesystem counters, identities, sizes, and nanosecond timestamps are integers when they fit; values beyond the signed integer range are returned as decimal strings instead of being truncated.

### Process jobs

`spawn_elf(path, args)` opens `path` with `READ | EXECUTE`, constructs bounded NUL-terminated UTF-8 arguments with `path` as `argv[0]`, creates the process with no ambient startup-handle dispositions or configuration, closes the executable file handle, and returns a positive terminal-local job ID. It reports an error and returns `-1` if validation or creation fails. At most 32 arguments including `argv[0]`, 16 KiB of startup bytes, and 32 retained jobs are accepted.

`spawn_installed(app_id, args)` resolves `app_id` through `applications/installed.gki`, uses the immutable generation path as `argv[0]`, and opens that file with `READ | EXECUTE`. Immediately before process creation it verifies the exact opened file's length and SHA-256 against the registry. It mints one application-data identity for the app and moves only a `READ`-attenuated identity into the child; no desktop channel, filesystem root, other startup handle, or startup configuration is supplied. A failed creation does not consume a move disposition, so the terminal closes the retained identity; successful creation consumes it atomically. The function follows the same argument/job limits as `spawn_elf` and returns a retained job ID or `-1`. `exec_installed(app_id, args)` performs the same verified launch, waits indefinitely, closes the process capability, and returns a status map or error string.

An installed child accesses its private directory by calling the Rust userspace API `application_get_data_directory()`. That directory authority comes only from the explicitly transferred application-data identity. It is not ambient filesystem authority and does not grant access to another application's data.

The headless job table is separate from graphical children and retains each process capability until `close_process(job_id)` or terminal shutdown. `process_status` and the infinite-wait `wait_process` return a map on success or an error string. The map's `state` is `running`, `exited`, `faulted`, or `terminated`; normal exits include `exit_code`, while faults include `fault`, `fault_code`, and `fault_address` (the code and address are fixed-width hexadecimal strings). `terminate_process` requests termination but retains the job handle. `exec_elf` is the synchronous convenience form for explicit paths and returns the same status map/error-string shape.

All direct execution functions are headless. This includes installed packages whose metadata kind is graphical: `spawn_installed` and `exec_installed` deliberately do not create or transfer a desktop channel. `run(app_id)` remains the graphical trusted-system-registry policy path: it creates a fresh bidirectional console channel and transfers the child endpoint through the desktop broker, which resolves the trusted registry ID and applies entry capabilities. Console-aware graphical children receive the endpoint as startup argument 3 (`rdx`), and the terminal polls its independently retained endpoint for `Output`, `Error`, and `Exit` messages.

### Machine power

The trusted terminal receives a non-transferable system-power capability. `power_off(confirmed, force)` and `reboot(confirmed, force)` reject calls unless `confirmed` is `true`; `force` permits the firmware transition after a bounded synchronization failure. `cancel_power()` cancels only during the two-second request interval. `power_status()` returns the current state (`idle`, `requested`, `quiescing`, `synchronizing`, `committing`, `canceled`, or `failed`), sequence, cancellation deadline, and failure status.

Once the cancellation interval expires, the kernel rejects new launches, gives existing processes a bounded grace interval, force-terminates remaining processes, checkpoints RedoxFS, explicitly flushes the block device, and invokes ACPI S5 or the FADT reset register. Ordinary and installed applications receive no system-power capability and direct requests fail authorization. The desktop launcher also exposes **Power off** and **Restart** rows; either requires a second click to confirm, and Escape cancels the confirmation.

### Package installation

`install_package(path)` accepts a bounded GKP file, validates it with `ginkgo-app-package`, and installs or updates its registry entry. `desktop`, `help`, `file-navigator`, `text-editor`, `terminal`, and `minimal-client` are protected system IDs and cannot be installed, updated, removed, or data-purged. `list_installed()` returns maps containing `app_id`, `display_name`, `version`, `kind`, the full immutable executable path, executable `sha256`, and package `package_sha256`.

Trusted built-in artifacts are separate from installed packages: the desktop, help app, file navigator, text editor, terminal, minimal client, and trusted program registry live at `/system/desktop.elf`, `/system/help.elf`, `/system/file-navigator.elf`, `/system/text-editor.elf`, `/system/terminal.elf`, `/system/minimal-client.elf`, and `/system/programs.gkr`. Userspace may read this top-level `/system` subtree but cannot open it for writing or use it as a create, truncate, unlink, directory-mutation, or rename source/target. Legacy trusted filenames at the root remain protected. During upgrade, boot moves an existing legacy artifact into `/system` when no destination exists, or removes the obsolete root duplicate after the `/system` copy is present; this space-safe migration runs before signed artifacts are refreshed and verified.

Package persistence uses the #4 hierarchy. The installed registry is `applications/installed.gki`, and its stage is `applications/installed.gki.new` in the same directory. Executable generations are stored at `applications/<app-id>/versions/<generation-filename>`, where the immutable filename is derived from the app ID and actual ELF SHA-256. Every installation creates `appdata/<app-id>/`, including executable-only packages. Package assets retain their exact validated relative paths beneath that directory; required parent directories are created idempotently, and an existing asset is preserved rather than overwritten. Authorized root-capability holders retain mutation access to both `applications` and `appdata`.

Registry publication writes and syncs the stage, reads it back through the bounded registry parser, and atomically renames it over the canonical registry with `REPLACE`, followed by a filesystem sync. The canonical registry is never truncated in place. Updates retain the old executable generation until that publication succeeds and then remove it. `uninstall_app(app_id)` first publishes the registry removal atomically, then removes the referenced executable and the now-empty `versions` and application directories. Application data is retained by default.

`purge_app_data(app_id)` is the explicit destructive data-removal operation. It validates and protects the application ID, preflights at most 512 files/directories and 32 levels beneath `appdata/<app-id>/`, rejects unknown entry kinds or larger trees before deleting anything, then removes the collected tree in child-first order and syncs the filesystem. A missing data tree is treated as already purged.

Installed-package launch uses the hierarchy registry and explicit process-startup authority described above. It does not alter the explicit-path behavior of `spawn_elf(path, args)` or `exec_elf(path, args)`, and it does not route user-installed graphical metadata through the trusted graphical launcher.

The service implements channel handling, protected three-buffer pools, server decorations with clickable close controls, focus, fullscreen, pointer/keyboard routing, and compositor placements. The top system tray reserves desktop space and shows uptime, graphical-process CPU use, physical-memory use, network availability, open graphical programs, and a Help launcher. Resize is generation-staged: the old frame remains displayed until the first new-generation present succeeds. Presented slots return to the client only through matching `BufferReleased` events. The compositor publishes bounded damaged regions from its persistent scene before completing a presentation.

All userspace and kernel channel queues are bounded. The service retains queued payloads and transferred surface handles after `ShouldWait`, retries after yielding, and limits work per scheduler turn. The minimal client treats empty reads and full writes as transient, submits one steady “Hello World” frame for each configuration, and does not repaint continuously after `BufferReleased`. The kernel does not auto-launch it; apps start only through an explicit launcher action.

`META+N` toggles the registry launcher, and Escape closes it. Integrated pane bindings are `META+Left/Right` (focus), `META+Q` (close the focused application), `META+A/S` (move left/right), `META+=/-` (width by 5%), and `META+L/C/R` (left/center/right alignment). Windows also expose a clickable X in the title bar. Columns scroll horizontally, so additional live applications may be off-screen and remain reachable with the focus bindings. The Help app repeats these controls inside the desktop. Remaining hotkey work is tracked in #5.
