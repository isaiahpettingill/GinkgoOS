# Software compositor

GinkgoOS keeps software composition as the display baseline. The compositor owns an XRGB8888 scene buffer for the active output and publishes only changed output rectangles.

## Persistent storage and allocation rules

The compositor keeps these buffers across frames:

- one XRGB8888 scene buffer sized to the output;
- one source-row scratch buffer sized to the widest registered surface;
- one selected-buffer slot per registered window;
- an eight-rectangle output damage region.

Output changes, surface configuration changes, and window registration may grow storage. An ordinary present after warm-up does not reserve, resize beyond capacity, or create a temporary `Vec`. `CompositorMetrics::storage_allocations` counts compositor-owned storage growth. Broker submission storage is reserved to the configured protected-buffer count when a surface pool is created. Each submission stores at most eight damage rectangles inline.

The runtime packet decoder still owns its decoded message while processing a present. After protocol decoding and channel warm-up, the kernel path reuses per-process channel syscall copy storage, broker submission storage, a persistent outbound encode buffer, handle-free channel message bytes, compositor storage, protected-buffer scratch, and framebuffer publication storage.

## Damage

Client damage is surface-local and half-open. An empty damage list means the complete source surface for compatibility with clients written before partial damage was used.

The runtime protocol carries damage in a fixed eight-rectangle value, so decoding an ordinary present does not allocate. The broker validates each rectangle against the configured pixel size. Empty or more fragmented input means complete-surface damage. The compositor maps source damage through scaling, intersects it with the client and visible rectangles, clips it to the output, and merges overlapping or edge-adjacent rectangles. If output damage exceeds eight disjoint rectangles, it falls back to complete-output damage.

Movement and resize damage both old and new visible areas. Registration and removal damage the affected visible area. Focus changes damage decorations only. Z-order changes damage the windows crossed by the move. A changed framebuffer address, pitch, dimensions, bit depth, or channel masks forces a complete redraw, including replacement framebuffers with the same dimensions.

Composition and publication are separate passes. Protected-buffer copy failures publish nothing. Damage is cleared only after framebuffer publication and protected presentation completion both succeed. If completion fails after publication, retained damage lets the next redraw repair the framebuffer from the still-displayed buffer.

## Occlusion

Opaque XRGB windows and server decorations occlude lower content. ARGB client pixels do not occlude lower windows because their alpha is not known until read. Letterbox bars are compositor-owned opaque pixels.

A pending surface fully covered by a selected opaque window is completed without reading its source buffer or writing the framebuffer. General composition also skips lower client pixels covered by opaque windows above them. Occlusion checks include only buffers selected for the current frame; a configured window with no displayed buffer cannot hide content.

## Protected-buffer ownership and coalescing

The displayed buffer remains protected until a later successful presentation releases it. The pending buffer remains protected while accepted or being copied.

When a newer present arrives before an unread pending buffer has been copied, the broker asks IPC to replace it atomically. IPC validates the replacement buffer before changing state, assigns a new presentation serial, and emits an exact release for the replaced serial. The broker unions damage from every replaced frame so changes relative to an intermediate frame are not lost. The displayed buffer is unchanged. Once any pending bytes have been copied, replacement returns `ShouldWait`; that frame must complete or be retried. Production surfaces use three protected buffers so one can remain displayed, one can remain pending, and the client can submit a replacement without releasing a buffer that the compositor may still read.

Release notifications consumed from protected IPC state are kept in preallocated broker storage if the desktop channel is full and retried before later packet processing. Runtime replies encode into persistent caller-owned bytes. Handle-free channel messages recycle their warmed byte buffers after each read.

## Frame clock and pacing

`DisplayFrameClock` defaults to an estimated 16,666,667 ns period (60 Hz). It exposes:

- refresh interval;
- next presentation deadline;
- timing confidence (`Estimated`, `Measured`, or `HardwareSynchronized`);
- paced or explicit immediate/debug mode.

The desktop task continues to process presentation packets without publishing them immediately. `DesktopBroker::compose_due` publishes only when the frame clock is due. In the normal path it selects every pending window, builds and publishes one combined scene, then completes each selected presentation. Early calls leave ownership unchanged. Late calls advance directly to the first future deadline and report skipped deadlines without an unbounded catch-up loop. The scheduler includes an active presentation deadline when arming its idle timer. Faster producers replace unread pending work when ownership allows it. Resize transitions keep their separate rollback path and force retained output damage before the first new-generation frame.

Cursor and launcher drawing still use kernel overlays. The desktop task hides the cursor before a due composition and redraws the launcher or cursor afterward, so overlay pixels do not become stale scene content.

`DesktopBrokerMetrics` reports submitted, composed, coalesced, dropped, late, and displayed frames, missed deadlines, externally measured duration, and a snapshot of compositor counters. `CompositorMetrics` reports damaged and published pixels, occluded presents, fullscreen fast paths, direct-copy rows, scaled work, and storage growth. The current firmware path combines scene rendering and framebuffer publication in one synchronous call, so the kernel records that total in `composition_duration_ns`; `publication_duration_ns` is reserved for a display backend that can timestamp publication separately.

## Scaling and fast paths

XRGB content whose source size exactly matches a topmost fullscreen output uses the fullscreen path. It skips lower-window composition, copies protected source rows directly into the persistent scene, and publishes them with packed framebuffer row stores.

Configured desktop surfaces map their pixel size to the matching logical client size, including fractional-scale rounding, without accidental letterboxing. For other source/client size mismatches, nearest-neighbor is the default game-oriented path. Upscaling uses the largest whole-number scale that fits the client. Downscaling fits the source aspect ratio to the client. Both paths center the result without changing aspect ratio, and uncovered client pixels are black letterbox bars. Damage is mapped outward so every destination pixel sampling a changed source pixel is included.

The output-native scene format is little-endian XRGB8888. Native 32-bit XRGB framebuffers use checked packed `u128`, `u64`, and `u32` volatile row stores. Unaligned rows use byte stores. Other firmware RGB layouts use their channel masks for exact conversion, including BGR shifts. Pixels and row padding outside the requested region are untouched.

## Framebuffer caching

The current Limine framebuffer arrives through bootloader-owned mappings. GinkgoOS does not yet have a safe physical-address and alias contract that would let it replace those mappings with PAT write-combining pages without risking conflicting cache types. The compositor therefore keeps the firmware mapping as the safe fallback and concentrates writes into packed damaged rows. A future display backend should create one owned framebuffer mapping, program a PAT write-combining entry, avoid cache-type aliases, and fall back to the firmware mapping when PAT setup or page ownership cannot be proved.

## TinySkia evaluation

TinySkia was not added to the kernel compositor. Its path, mask, paint, and antialiasing code helps richer UI primitives, but it does not provide damage tracking, ownership barriers, occlusion, pacing, fullscreen selection, or framebuffer publication. Adding it to the current rectangle/frame path would increase kernel code and adaptation work without removing a hot-path allocation or copy.

If #32 adopts TinySkia for userspace UI, it should live behind a `ginkgo-raster` adapter over persistent caller-owned premultiplied RGBA bytes using `PixmapMut::from_bytes`. The adapter must bound dimensions, reuse paths/paints/masks, and convert explicitly between premultiplied RGBA and Ginkgo XRGB/ARGB. Applications should depend on that userspace abstraction, not compositor internals.

## Tests and benchmark

Focused tests cover region clipping/merging/fallback, source-local damage, unchanged output pixels, same-size output replacement, XRGB and ARGB behavior, decoration snapshots, occlusion without source reads, release ownership, atomic coalescing, completion repair, nearest-neighbor scaling, letterboxing, fullscreen selection, frame deadlines, and packed/mask-aware framebuffer publication.

Run the manual host benchmark with:

```sh
cargo test -p ginkgo-kernel --lib --target x86_64-pc-windows-msvc \
  benchmark_1080p_full_frame_against_small_damage -- --ignored --nocapture
```

Reference result from the development Windows host on 2026-07-25:

| Workload | Frames | Total time | Mean per frame | Published bytes |
| --- | ---: | ---: | ---: | ---: |
| 1920×1080 full frame | 60 | 58.069 ms | 0.968 ms | 497,664,000 |
| 64×64 damage at 1920×1080 | 60 | 0.150 ms | 0.003 ms | 983,040 |

This is a host RAM-framebuffer reference, not a QEMU or Haswell hardware result. QEMU and target Haswell runs must use the same 1920×1080 scene, 60-frame count, release cycle, and build revision. Record CPU model, framebuffer cache policy, full and damaged time, bytes, frame-clock misses, and coalesced/dropped counts. Hardware write-combining numbers must not be claimed until the display backend owns a PAT-safe mapping.
