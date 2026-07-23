# GinkgoOS userspace workspace

This is the production, nested `x86_64-unknown-none` workspace. It is intentionally independent of the kernel's root Cargo workspace.

## Packages

- `ginkgo-runtime`: shared `no_std` talc static heap, panic/exit handling, `_start` entry macro, linker script, and build-script helper.
- `ginkgo-desktop-service`: production window-policy service using `ginkgo_desktop::Desktop`, the broker runtime protocol, per-app channels, and protected two-buffer surface pools.
- `ginkgo-minimal-client`: production syscall-backed `WindowTransport`/`WindowClient` demo with a centered “Hello World” surface and `F11` fullscreen toggling.
- `ginkgo-file-navigator`: keyboard-controlled `/user` workspace browser; Up/Down selects, Enter enters a directory or securely launches the text editor for a file, Backspace returns, and Delete removes entries.
- `ginkgo-text-editor`: persistent UTF-8 editor scoped to `/user`, with open/save/save-as, selection, clipboard, undo/redo, and startup document requests from the file navigator.
- `ginkgo-terminal`: terminal emulator and bounded Rhai shell. Keyboard input and graphical child output use framed Ginkgo channel messages rather than file descriptors. Scripts can perform root file I/O, launch and inspect headless ELF jobs through process capabilities, manage bounded GKP installations, source another script, and request registry-governed graphical launches.
- `validator`: host-only copy of the existing validation harness pattern which imports the kernel ELF parser directly.

## Build and validate

Normal root Makefile builds compile the production ELFs before the kernel and pass their paths into the kernel build for embedding as `/system/desktop.elf`, `/system/file-navigator.elf`, `/system/text-editor.elf`, `/system/minimal-client.elf`, and `/system/terminal.elf` alongside `/system/programs.gkr`.

```sh
cargo build --release --target x86_64-unknown-none -p ginkgo-desktop-service -p ginkgo-file-navigator -p ginkgo-text-editor -p ginkgo-minimal-client -p ginkgo-terminal
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
- `target/x86_64-unknown-none/release/ginkgo-file-navigator`
- `target/x86_64-unknown-none/release/ginkgo-text-editor`
- `target/x86_64-unknown-none/release/ginkgo-terminal`

## Runtime integration

The kernel boots `ginkgo-desktop-service` with only one bootstrap channel and the output dimensions. It creates the persistent `/user` workspace idempotently and launches ordinary registered applications with a non-transferable, non-duplicable `READ | WRITE` directory capability rooted there; paths cannot escape to `/system`, `/applications`, or `/appdata`. The trusted terminal is the exception: package management and explicit executable launch require its existing root `READ | WRITE | EXECUTE` authority, but its logical starting directory is `/user`. The service and kernel broker provision protected shared-memory surfaces and client/manager capabilities. The boot registry exposes `Files`, `Text Editor`, `Terminal`, and `Ginkgo Demo` while keeping the desktop service hidden. General launch authority remains terminal-only; the file navigator has a separate narrow permission that can launch only the trusted text editor for a selected document.

## Terminal shell

The prompt preprocesses Ginkgo command syntax and then evaluates ordinary Rhai. Interactive input and `source` scripts use the same token-aware preprocessor. Registered commands support shell-style arguments, aliases, `$(...)` Rhai interpolation, and structured F#-style pipelines; registered names followed by normal Rhai call/member/index/assignment syntax remain unchanged.

```text
ls
ls /system
cd documents
pwd
cat "notes with spaces.txt"
cp notes.txt backup.txt
mv backup.txt archive.txt
rm archive.txt
mkdir drafts
rmdir drafts
clear
ps
kill 1
print "hello from Rhai"
help
help ls

@edit
@files
@minimal-client
@tools/example.elf --verbose $(option)

let extension = ".rhai";
ls /system |> filter(extension) |> sort |> print
```

Built-in canonical names and aliases are:

| Canonical name | Aliases | Result |
| --- | --- | --- |
| `list_files` | `ls`, `dir` | Structured directory-entry array |
| `change_directory` | `cd`, `chdir` | Changes the terminal's capability-rooted logical directory |
| `current_directory` | `pwd`, `cwd` | Logical directory beginning at `/` |
| `copy` | `cp` | Copies one file without escaping the filesystem capability |
| `move` | `mv`, `ren`, `rename` | Moves or renames without replacing an existing destination |
| `remove` | `rm`, `del`, `delete` | Removes one or more files |
| `make_directory` | `mkdir`, `md` | Creates one or more directories |
| `remove_directory` | `rmdir`, `rd` | Removes one or more empty directories |
| `show_file` | `cat`, `type` | Returns file text |
| `clear_terminal` | `clear`, `cls` | Clears terminal scrollback |
| `show_processes` | `ps`, `tasks` | Structured terminal-owned job array |
| `terminate_process` | `kill`, `stop` | Terminates a terminal-owned job ID |
| `print` | `output` | Evaluates and prints one Rhai expression |
| `help` | — | Shows the command/syntax summary or detailed command help |

Shell arguments are literal strings unless wrapped in `$(...)`. Pipelines pass Rhai `Dynamic` values rather than formatted terminal text. For example, `ls /system` returns entry maps that `filter`, `sort`, and later stages consume directly. Directory-entry arrays and terminal-job arrays are rendered as compact tables when printed; other arrays render one item per line. Unknown identifiers are left to Rhai and are never guessed to be commands.

A statement-boundary `@` sigil launches executables without adding every application to the command registry. `@edit` and `@editor` launch `text-editor`; `@files` launches `file-navigator`; `@demo` launches `minimal-client`; and any other bare target is passed to the trusted graphical program registry as its application ID. Targets ending in `.elf` or containing `/` are opened beneath the terminal's filesystem capability and started as headless terminal jobs; following shell arguments become process arguments. Graphical launch arguments are rejected because the desktop launch protocol does not currently carry an argument vector. Executable launches cannot be pipeline inputs.

Ordinary Rhai remains available and unchanged:

```rhai
print("hello from Rhai");
list_files() // compatibility: root entry names
mkdir("documents")
write_file("documents/notes.txt", "persistent text")
append_file("documents/notes.txt", "\nmore")
read_file("documents/notes.txt")
file_size("documents/notes.txt")
metadata("documents/notes.txt")
list_directory("documents")
rename_path("documents/notes.txt", "documents/archive.txt", false)
remove_file("documents/archive.txt")
rmdir("documents")
filesystem_info()
sync_filesystem()
syscall("yield")

// Direct ELF execution is headless and receives no transferred startup handles.
let job = spawn_elf("hello.elf", ["--verbose"]);
process_status(job)
wait_process(job)
terminate_process(job)
close_process(job)
exec_elf("one-shot.elf", ["input.txt"])

install_package("paint.gkp")
list_installed()
let installed_job = spawn_installed("tools.paint", ["document.gkg"]);
wait_process(installed_job)
close_process(installed_job)
exec_installed("tools.paint", ["document.gkg"])
uninstall_app("tools.paint")       // preserves appdata/tools.paint/
purge_app_data("tools.paint")      // explicit recursive data removal

// Graphical applications continue through registry and desktop policy.
run("minimal-client")
```

Enter `source "script.rhai"` to preprocess and evaluate another script relative to the terminal's logical directory, initially `/user`. A leading `/` explicitly addresses the trusted terminal's filesystem root.

### Filesystem functions

All terminal filesystem access remains beneath its explicit trusted filesystem-root capability. The shell starts in `/user`; shell commands, sourced scripts, and `@` executable paths resolve relative to that logical directory. A leading `/` addresses the capability root, and normalization rejects attempts to ascend above it. Low-level Rhai filesystem functions remain explicit capability-root-relative APIs. The kernel has no ambient current-working-directory state: ordinary graphical processes instead receive `/user` itself as their scoped filesystem capability, so their relative paths naturally remain in the user workspace.

- `mkdir(path)` creates one directory at `path`; parent directories must already exist.
- `rmdir(path)` removes an empty directory.
- `rename_path(source, destination, replace)` atomically renames or moves a file or directory beneath the same root. If `replace` is `false`, an existing destination causes failure; if it is `true`, a compatible destination may be replaced.
- `sync_filesystem()` flushes pending filesystem data and metadata.
- `filesystem_info()` returns capacity and limit fields (`total_bytes`, `free_bytes`, `available_bytes`, `block_size`, `max_name_length`, `max_path_depth`, and `read_only`) or an error string.
- `metadata(path)` returns `kind`, stable `identity`, numeric `mode`, `size`, and a `time` map containing `created_ns` and `modified_ns`, or an error string.
- `list_directory(path)` returns up to 256 rich entry maps with `name` plus the same kind, identity, mode, size, and time fields. It reports an error and returns an empty array on failure.
- `list_files()` remains the compatibility form and returns up to 256 root entry names.

Filesystem counters, identities, sizes, and nanosecond timestamps are Rhai integers when they fit; values beyond the signed integer range are returned as decimal strings instead of being truncated.

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

`install_package(path)` accepts a bounded GKP file (currently capped at 1 MiB to fit the terminal's 2 MiB static heap), validates it with `ginkgo-app-package`, and installs or updates its registry entry. `desktop`, `file-navigator`, `terminal`, and `minimal-client` are protected system IDs and cannot be installed, updated, removed, or data-purged. `list_installed()` returns maps containing `app_id`, `display_name`, `version`, `kind`, the full immutable executable path, executable `sha256`, and package `package_sha256`.

Trusted built-in artifacts are separate from installed packages: the desktop, file navigator, terminal, minimal client, and trusted program registry live at `/system/desktop.elf`, `/system/file-navigator.elf`, `/system/terminal.elf`, `/system/minimal-client.elf`, and `/system/programs.gkr`. Userspace may read this top-level `/system` subtree but cannot open it for writing or use it as a create, truncate, unlink, directory-mutation, or rename source/target. Legacy trusted filenames at the root remain protected. During upgrade, boot moves an existing legacy artifact into `/system` when no destination exists, or removes the obsolete root duplicate after the `/system` copy is present; this space-safe migration runs before signed artifacts are refreshed and verified.

Package persistence uses the #4 hierarchy. The installed registry is `applications/installed.gki`, and its stage is `applications/installed.gki.new` in the same directory. Executable generations are stored at `applications/<app-id>/versions/<generation-filename>`, where the immutable filename is derived from the app ID and actual ELF SHA-256. Every installation creates `appdata/<app-id>/`, including executable-only packages. Package assets retain their exact validated relative paths beneath that directory; required parent directories are created idempotently, and an existing asset is preserved rather than overwritten. Authorized root-capability holders retain mutation access to both `applications` and `appdata`.

Registry publication writes and syncs the stage, reads it back through the bounded registry parser, and atomically renames it over the canonical registry with `REPLACE`, followed by a filesystem sync. The canonical registry is never truncated in place. Updates retain the old executable generation until that publication succeeds and then remove it. `uninstall_app(app_id)` first publishes the registry removal atomically, then removes the referenced executable and the now-empty `versions` and application directories. Application data is retained by default.

`purge_app_data(app_id)` is the explicit destructive data-removal operation. It validates and protects the application ID, preflights at most 512 files/directories and 32 levels beneath `appdata/<app-id>/`, rejects unknown entry kinds or larger trees before deleting anything, then removes the collected tree in child-first order and syncs the filesystem. A missing data tree is treated as already purged.

Installed-package launch uses the hierarchy registry and explicit process-startup authority described above. It does not alter the explicit-path behavior of `spawn_elf(path, args)` or `exec_elf(path, args)`, and it does not route user-installed graphical metadata through the trusted graphical launcher.

The service implements channel handling, protected two-buffer pools, server decorations, focus, fullscreen, pointer/keyboard routing, and compositor placements. Resize is generation-staged: the old frame remains displayed until the first new-generation present succeeds. Presented slots return to the client only through matching `BufferReleased` events. The compositor assembles a complete scene in RAM and publishes it with packed framebuffer writes before completing a presentation.

All userspace and kernel channel queues are bounded. The service retains queued payloads and transferred surface handles after `ShouldWait`, retries after yielding, and limits work per scheduler turn. The minimal client treats empty reads and full writes as transient, submits one steady “Hello World” frame for each configuration, and does not repaint continuously after `BufferReleased`. The kernel does not auto-launch it; apps start only through an explicit launcher action.

`META+N` toggles the registry launcher. Integrated pane bindings are `META+Left/Right` (focus), `META+Q` (close the focused application), `META+A/S` (move left/right), `META+=/-` (width by 5%), and `META+L/C/R` (left/center/right alignment). Columns scroll horizontally, so additional live applications may be off-screen and remain reachable with the focus bindings. Remaining hotkey work is tracked in #5.
