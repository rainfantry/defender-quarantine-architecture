# Discovery Narrative: How the Dual-Layer Architecture Was Mapped

**Author:** George Wu (22DIV)

This document records the iterative experimental process that led to the architectural findings. Each failed attack variant revealed a new defensive layer. The research is presented in chronological order to show how each finding informed the next experiment.

---

## Phase 1: The Starting Assumption (v1-v5)

The initial assumption — shared by most published TOCTOU research — was that Defender's quarantine pipeline works like this:

```
Scan file at path X → Decide malicious → Re-open path X → Delete file at path X
```

If the attacker can replace the directory at path X with an NTFS junction between the scan and the re-open, Defender deletes whatever the junction points to. The exploit requires:

1. A file that triggers detection (EICAR)
2. A timing mechanism to know when Defender is in the gap (oplock)
3. A fast swap operation (junction creation)

Five iterative versions were built and tested. Each one failed, and each failure revealed a new defensive mechanism.

### v2 — ERROR 225: Scan-on-Write

**Hypothesis:** Write EICAR, then open a second handle for oplock.

**Result:** `ERROR_VIRUS_INFECTED` (225) on the second `CreateFile`.

**Discovery:** WdFilter scans inline on `IRP_MJ_WRITE`, not just on handle close. The file is flagged in WdFilter's internal cache the instant malicious content is written. Any subsequent `CreateFile` on a flagged file is rejected immediately.

This is more aggressive than the commonly documented "scan-on-close" behavior.

### v3 — ERROR 300: Oplock Sole Handle Requirement

**Hypothesis:** Create empty file first, open oplock handle, then write EICAR.

**Result:** `ERROR_OPLOCK_NOT_GRANTED` (300) on `DeviceIoControl`.

**Discovery:** Batch oplocks require the requesting handle to be the sole FILE_OBJECT on the file. Two open handles — even from the same process — cause the oplock request to fail. The write handle was still open when the oplock was requested.

### v4 — Deadlock: Single-Thread Self-Deadlock

**Hypothesis:** Close write handle, arm oplock as sole handle, re-open for write.

**Result:** Program hangs after "Tripwire ARMED."

**Discovery:** Each `CreateFile` call creates a new FILE_OBJECT. The oplock subsystem evaluates compatibility per-FILE_OBJECT, not per-process. The re-open triggers an oplock break, but the thread that needs to acknowledge the break IS the thread that's blocked inside `CreateFile`. Classic deadlock.

This corrects a common assumption in exploit literature that "same-process opens are safe with batch oplocks." They are only safe if the opener runs on a different thread.

### v5 — Timeout: Handle-Aware Quarantine Deferral

**Hypothesis:** Write through the oplock handle itself (no new FILE_OBJECT).

**Result:** All phases GREEN — but 10-second timeout. Defender detects EICAR (notification visible) but never breaks the oplock.

**Discovery:** WdFilter defers quarantine while handles remain open. The detection fires (user notification displayed), but remediation waits for `IRP_MJ_CLEANUP` (all handles closed). The oplock catch-22: keeping the handle open prevents quarantine; closing it removes the timing mechanism.

### v6 — All Phases GREEN, BDA Negative: Cached FILE_OBJECT

**Hypothesis:** Two-thread design. Thread A holds oplock. Thread B writes and closes, triggering Defender into Thread A's oplock. Thread A catches break, swaps junction.

**Result:** ALL phases fire. Swap executes in 0.6-2.3ms. Junction planted. BDA (Battle Damage Assessment) at target: NEGATIVE.

**Discovery:** ProcMon filtered for MsMpEng.exe + bait path showed ZERO operations. Defender quarantines regular files through **cached FILE_OBJECT references** — direct kernel pointers that bypass path resolution entirely. The junction is invisible because no path traversal occurs during quarantine.

This is the pivotal finding: regular file quarantine is architecturally immune to junctions.

---

## Phase 2: Forcing Path-Based Operations (v7)

### v7/BB4 — Cloud Files Mechanism Test

**Hypothesis:** Cloud Files placeholders may force Defender into a different quarantine code path.

**Result:** 333 ProcMon events across two runs. MsMpEng.exe issues 28+ `CreateFile` calls BY PATH during quarantine of Cloud Files placeholders. All calls traverse NTFS namespace.

**Discovery:** The quarantine pipeline has two distinct modes:
- Regular files → cached FILE_OBJECT (junction-immune)
- Cloud Files placeholders → path-based operations (junction-visible)

Additional observation: a 5-second gap between scan completion and quarantine start for Cloud Files, vs. near-instant for regular files.

### v7a — Junction Traversal Confirmed

**Hypothesis:** If Cloud Files quarantine is path-based, junctions will be followed.

**Result:** ProcMon shows `REPARSE → SUCCESS` on junction path. MsMpEng.exe opens, reads, and queries files at the junction target. BDA NEGATIVE — quarantine aborts without deleting.

**Discovery (Finding #11):** Junction traversal CONFIRMED. MsMpEng.exe follows junctions during Cloud Files quarantine. But quarantine re-reads content at the resolved path. Clean file at target → quarantine aborts.

**Discovery (Finding #12):** SYSTEM read primitive CONFIRMED. MsMpEng.exe (SYSTEM) reads 16 bytes from target through junction. Information disclosure boundary violation — standard user forces SYSTEM-level file read.

### v7b — CfExecute Write Primitive Test

**Hypothesis:** If junction swap happens during the hydration callback (before CfExecute writes data), the hydrated content will write to the junction target.

**Result:** Swap succeeds inside callback (5-14ms). CfExecute returns `ERROR_FILE_NOT_FOUND` (0x80070002) x3.

**Discovery (Finding #14):** CfExecute is FILE_OBJECT-based. It uses the kernel reference captured at placeholder creation, not path resolution. Deleting the original file and replacing with a junction causes CfExecute to fail. Write primitive via CfExecute is dead.

**Discovery (Finding #15):** CfExecute delivers data to the reader's buffer in-memory even when the disk write fails. 68 bytes received by Thread B. No WdFilter scan occurs (no Error 225). This is a memory-only data channel below WdFilter's minifilter altitude.

---

## Phase 3: Bypassing the Re-Verification Gate (v8)

### v8a — EICAR at Junction Target

**Hypothesis:** If a file with identical malicious content exists at the junction target (same filename, same EICAR content), the re-verification scan will find matching content and proceed with quarantine → SYSTEM deletes target file.

**Result:** BDA NEGATIVE x3. Target file survives.

**Full ProcMon analysis (481 events, 4 quarantine bursts):**

```
Burst 1 (lines 1-100): Junction-redirect quarantine
  - REPARSE → SUCCESS (junction followed ✓)
  - ReadFile 68 bytes at target (EICAR found ✓)
  - FSCTL_READ_FILE_USN_DATA (USN captured)
  - QueryIdInformation (File ID captured)
  - Compare against original detection → MISMATCH → ABORT
  - ZERO SetDispositionInformationFile

Burst 2 (lines 111-296): Direct EICAR quarantine (from Phase 0 write)
  - No REPARSE (direct path)
  - FILE_LOCKED, full scan, extension probes
  - File quarantined (disappears at 7:35:11.74)
  - STILL zero SetDispositionInformationFile from MsMpEng.exe

Burst 3-4 (lines 317-480): Re-engagement attempts
  - Identical abort pattern — identity mismatch
```

**Discovery (Finding #16 — Dual-Layer Architecture):**

The 481-event ProcMon trace revealed the complete picture:

1. **Zero `SetDispositionInformationFile`** in the entire trace. MsMpEng.exe (user-mode) NEVER issues a delete syscall.

2. **The actual delete is performed by WdFilter.sys** (kernel minifilter) through cached FILE_OBJECT references. WdFilter is invisible to ProcMon's process-name filter because it operates inside the kernel's I/O path, not as a named process.

3. **MsMpEng.exe's path-based pipeline is purely investigative.** It reads, queries metadata, checks identity — but never modifies or deletes. Its role is to VERIFY, not to ACT.

4. **The re-verification gate checks IDENTITY, not content.** NTFS File ID is an immutable 64-bit identifier assigned at file creation. Two different files cannot share the same File ID, regardless of content. USN journal sequence numbers provide additional temporal identity.

5. **The identity gate is architecturally unbypassable through junctions.** A junction redirects path resolution, but the file at the resolved path has its own File ID. The mismatch between the original detection (placeholder's File ID) and the target (target file's File ID) will always trigger an abort.

---

---

## Phase 4: Custom Scan — A Different Pipeline (v8b)

### v8b — Custom Scan Quarantine Mechanism Probe

**Hypothesis:** Custom scans triggered via `MpCmdRun.exe -Scan -ScanType 3` may use a different quarantine pipeline than RTP. If the pipeline is path-based, the delete may be junction-exploitable.

**Design:** Two engagements. Engagement 1: baseline custom scan of EICAR (no junction) — look for `SetDispositionInformationFile`. Engagement 2: custom scan through junction — look for delete on target path.

**Result (Engagement 1):** `SetDispositionInformationFile` appears at line 383 of the ProcMon trace.

```
Line 383: MsMpEng.exe  SetDispositionInformationFile  bait.exe  SUCCESS  Delete: True
```

This operation has **never** appeared in any RTP trace (0 in 481+ events). Custom scan quarantine uses a path-based delete from MsMpEng.exe user-mode code. This is fundamentally different from RTP's WdFilter FILE_OBJECT delete.

**Additional observations from Engagement 1:**
- 12 `FSCTL_GET_REPARSE_POINT` checks throughout the quarantine burst — active reparse point scanning on the parent directory (all returned `NOT REPARSE POINT`)
- Volume Shadow Copy access: MsMpEng reads from `\Device\HarddiskVolumeShadowCopy1\` during quarantine — cross-referencing file's historical state
- 28ms window between last reparse point check and `SetDispositionInformationFile`

**Result (Engagement 2 — junction present):** Junction traversal confirmed. REPARSE → SUCCESS. MsMpEng reads 68 bytes from target through junction (SYSTEM read primitive). Full metadata investigation including two `QueryIdInformation` cycles. But quarantine **ABORTED** — zero `SetDispositionInformationFile` in the entire engagement.

**Discovery (Finding #17 — Custom Scan Path-Based Delete):** Custom scan quarantine uses `SetDispositionInformationFile` from MsMpEng.exe — a path-based delete that WOULD follow junctions if it fired. Three distinct quarantine architectures now identified:

1. **RTP (regular files):** WdFilter FILE_OBJECT delete — junction-immune by design
2. **RTP (Cloud Files):** MsMpEng verify-only (path-based) + WdFilter FILE_OBJECT delete — verify follows junctions but delete doesn't
3. **Custom scan:** MsMpEng `SetDispositionInformationFile` — path-based delete, mitigated by reparse point awareness and identity gate

**Discovery (Finding #18 — Reparse Point Awareness):** MsMpEng explicitly opens directories with `Open Reparse Point` flag and checks for `DRP` (Directory + Reparse Point) in `FileAttributes`. When detected, quarantine runs its full investigation but aborts before issuing the delete. This is a **separate defense** from the identity gate — junction-specific detection.

```
Line 406: CreateFile  vader_jnx  → SUCCESS  (Options: Open Reparse Point)
Line 407: QueryNetworkOpenInfo   → FileAttributes: DRP
```

**Discovery (Finding #19 — VSS Cross-Reference):** Custom scan reads from Volume Shadow Copy during quarantine (not observed in RTP). Provides temporal integrity checking.

---

## Summary of Defensive Layers Discovered

| Layer | Mechanism | What It Blocks | Discovered In |
|-------|-----------|---------------|---------------|
| Scan-on-write | WdFilter inline scan | Opening handles after malicious write | v2 |
| Oplock exclusivity | Kernel FILE_OBJECT semantics | Single-threaded oplock attacks | v3-v4 |
| Handle-aware deferral | WdFilter deferred remediation | Oplock catch-22 for single-handle designs | v5 |
| FILE_OBJECT quarantine | WdFilter cached references | All junction attacks on regular files | v6 |
| Identity re-verification | MsMpEng File ID + USN check | Content-matching junction attacks | v8a |
| Kernel-layer delete | WdFilter FILE_OBJECT delete | Path-based delete even if re-verification passed | v8a |
| CfExecute FILE_OBJECT | cldflt.sys cached references | Write-primitive via hydration redirect | v7b |
| Reparse point awareness | MsMpEng DRP attribute check | Junction-redirected custom scan delete | v8b |
| VSS cross-reference | MsMpEng VSS snapshot comparison | File tampering between scan and quarantine | v8b |

Each layer was discovered by building an attack that bypassed all previously known layers and observing what stopped it next. The cumulative result is a **nine-layer** defense-in-depth architecture that blocks all tested destructive primitives while leaving a narrow read-primitive channel open.

**Note on the custom scan pathway:** The custom scan quarantine is the only architecture where the delete mechanism itself (SetDispositionInformationFile) is path-based. The reparse point awareness check and identity gate prevent junction-redirected deletion, but these are verification-based defenses rather than architectural ones. This makes the custom scan pathway the narrowest defense margin in the system.
