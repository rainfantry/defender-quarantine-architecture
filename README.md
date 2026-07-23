# Windows Defender Quarantine Architecture: A Defense-in-Depth Analysis

**Author:** George Wu ([22DIV](https://github.com/rainfantry))
**Date:** June 2026
**Platform:** Windows 11 Home 24H2 (Build 26200)
**Defender Engine:** 1.1.26050.11 / Platform 4.18.26050.15

---

## Purpose

This document presents original research into the internal architecture of Windows Defender's quarantine pipeline, with focus on how it handles NTFS junction traversal, file identity verification, and the interaction between its kernel-mode and user-mode components.

The goal is defensive: to help security professionals, system administrators, and researchers understand the specific mechanisms that protect (and don't protect) against symlink-based attacks targeting antivirus quarantine operations.

**This repository contains no exploit code.** All findings are architectural observations derived from empirical testing using ProcMon, the EICAR test standard, and standard Win32 APIs.

---

## Table of Contents

1. [Background](#1-background)
2. [Methodology](#2-methodology)
3. [Architecture Overview](#3-architecture-overview)
4. [Key Findings](#4-key-findings)
5. [Primitive Analysis](#5-primitive-analysis)
6. [Defensive Recommendations](#6-defensive-recommendations)
7. [Responsible Disclosure](#7-responsible-disclosure)
8. [Forward Application](#8-forward-application-what-the-architecture-taught-us)
9. [References](#9-references)

---

## 1. Background

### 1.1 The TOCTOU Attack Class

Time-of-Check to Time-of-Use (TOCTOU, CWE-367) vulnerabilities exist whenever a program checks a condition and then acts on it, with a window between the two where the condition can change. In the context of antivirus software, this manifests as:

1. **Check:** AV scans a file at path X, determines it is malicious.
2. **Gap:** Time passes while the AV prepares its quarantine action.
3. **Use:** AV returns to path X to quarantine (delete/move) the file.

If an attacker can redirect path X between steps 1 and 3 (e.g., by replacing a directory with an NTFS junction), the AV's quarantine action operates on a different file than the one it scanned. Because antivirus services typically run as `NT AUTHORITY\SYSTEM`, this can result in SYSTEM-privileged file operations on attacker-chosen targets.

### 1.2 NTFS Junctions

NTFS junctions (reparse points with tag `IO_REPARSE_TAG_MOUNT_POINT`) are directory-level symbolic links. Key properties:

- Standard users can create them on directories they own
- The kernel resolves them transparently during path traversal
- Any process traversing a path containing a junction is redirected
- No special privilege is required to create a junction
- Junctions survive process restarts and are persistent on disk

### 1.3 Prior Work

Published TOCTOU exploits against Windows Defender (by various researchers) have been signatured by Microsoft, typically within days of publication. These exploits used mechanisms like Cloud Files API (`CldApi.dll`) or virtual disk mounts (`virtdisk.lib`) to force path-based operations in Defender's quarantine pipeline.

This research independently maps the internal architecture to understand *why* some approaches work and others don't, and *which defensive layers* protect against each attack variant.

### 1.4 Cloud Files API

The Windows Cloud Files API (`CldApi.dll`) enables applications to register as sync providers and create placeholder files. Placeholder files appear in the filesystem but have no on-disk content until "hydrated" — when an application reads them, the sync provider is called back to deliver the data.

Cloud Files placeholders are relevant to this research because they trigger fundamentally different behavior in Defender's quarantine pipeline compared to regular files.

---

## 2. Methodology

### 2.1 Test Environment

| Property | Value |
|----------|-------|
| OS | Windows 11 Home Build 26200 (24H2) |
| User Privilege | Standard (non-admin) |
| Defender RealTime Protection | Enabled |
| Tamper Protection | Off |
| HVCI | Running |
| Behavior Monitoring | Enabled |

All testing was performed on personally-owned hardware under academic security research authorization.

### 2.2 Tools

| Tool | Purpose |
|------|---------|
| ProcMon (Sysinternals) | File system, registry, and process monitoring at the IRP level |
| EICAR test pattern | Industry-standard AV test file (68 bytes, detected by all AV vendors) |
| Custom C programs | Minimal test harnesses using Win32 API (kernel32.dll only) |
| cl.exe (MSVC) | Compilation with `/O1 /GS-` for minimal binary footprint |
| Windows Event Viewer | Defender detection and quarantine event correlation |

### 2.3 Approach

Each test engagement followed a controlled experiment structure:

1. **Hypothesis** — What specific behavior is being tested?
2. **Design** — Minimal test case isolating one variable
3. **Execution** — Run with ProcMon capture, full process/path filtering
4. **Analysis** — Parse ProcMon CSV for specific IRP operations
5. **Finding** — Document observed behavior with evidence

The research progressed through 17 iterative experiments (v1 through v8b), each building on the findings of the previous one.

### 2.4 EICAR Test Standard

All detection triggers used the EICAR Anti-Malware Test File — a standardized 68-byte string that all AV products detect as "malicious" for testing purposes. No actual malware was used at any point.

The EICAR string is XOR-encoded in test binaries (key `0x5A`) and decoded at runtime, preventing the test binary itself from triggering static analysis detection during compilation or storage.

---

## 3. Architecture Overview

### 3.1 The Dual-Layer Quarantine Architecture

The most significant finding of this research is that Windows Defender's quarantine pipeline operates as a **dual-layer system** with fundamentally different security properties at each layer.

```
┌──────────────────────────────────────────────────────────────────┐
│                    QUARANTINE PIPELINE                           │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  LAYER 2 — MsMpEng.exe (User-mode service, SYSTEM)        │  │
│  │  ─────────────────────────────────────────────────────     │  │
│  │  • Path-based re-verification pipeline                    │  │
│  │  • 28+ CreateFile calls by path (for Cloud Files)         │  │
│  │  • Reads content at resolved path                         │  │
│  │  • Identity checks: File ID + USN comparison              │  │
│  │  • FOLLOWS NTFS junctions (REPARSE → SUCCESS)             │  │
│  │  • RTP: purely investigative — never issues delete         │  │
│  │  • Custom Scan: issues SetDispositionInformationFile       │  │
│  │  •   (path-based delete, guarded by DRP check)            │  │
│  │  • Some operations impersonate triggering user            │  │
│  └───────────────────────┬────────────────────────────────────┘  │
│                          │ identity match + no DRP?              │
│                          │ YES → delete (custom) / signal (RTP)  │
│                          │ NO  → ABORT (no quarantine)           │
│  ┌───────────────────────▼────────────────────────────────────┐  │
│  │  LAYER 1 — WdFilter.sys (Kernel minifilter, ring 0)       │  │
│  │  ─────────────────────────────────────────────────────     │  │
│  │  • Intercepts file I/O via minifilter callbacks            │  │
│  │  • Caches FILE_OBJECT references at detection time         │  │
│  │  • Defers quarantine while handles remain open             │  │
│  │  • Executes DELETE through cached FILE_OBJECT              │  │
│  │  • IMMUNE to NTFS junctions (no path resolution)           │  │
│  │  • Actual destructive operation (move + delete)            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Key insight (RTP):** The layer that follows junctions (Layer 2) never deletes. The layer that deletes (Layer 1) never follows junctions. This architectural separation is a robust defense-in-depth mechanism, likely by design.

**Key insight (Custom Scan):** Layer 2 both follows junctions AND can issue deletes (`SetDispositionInformationFile`). However, a reparse point awareness check (Finding 13) detects junctions and aborts before the delete fires. The defense here is verification-based rather than architectural.

### 3.2 Detection vs. Remediation Decoupling

Defender decouples detection from remediation:

| Phase | Component | Timing | Mechanism |
|-------|-----------|--------|-----------|
| Detection | WdFilter.sys | Synchronous (inline with I/O) | Scans on `IRP_MJ_WRITE` and `IRP_MJ_CLEANUP` |
| Notification | MsMpEng.exe | Near-real-time | Security notification displayed to user |
| Remediation | WdFilter.sys | Asynchronous (deferred) | Waits for all handles to close, then quarantines |

This decoupling means:
- A file is flagged immediately when written (user sees "Threats found" notification)
- Quarantine (deletion) does not occur until all open handles are closed
- There is no forced termination of handles — Defender waits patiently

### 3.3 Regular Files vs. Cloud Files Placeholders

The quarantine pipeline behaves fundamentally differently based on file type:

| Behavior | Regular File | Cloud Files Placeholder |
|----------|-------------|----------------------|
| Quarantine mechanism | Cached FILE_OBJECT | Path-based CreateFile (28+ calls) |
| Path resolution | None — direct kernel reference | Full NTFS namespace traversal |
| Junction visibility | Invisible | **Followed** (REPARSE → SUCCESS) |
| ProcMon visibility | Zero path operations from MsMpEng | 28+ CreateFile operations visible |
| Re-verification | N/A (same FILE_OBJECT) | Identity check (File ID + USN) |

This behavioral divergence is the enabling condition for junction-based attacks. An attacker must use Cloud Files placeholders (or equivalent mechanism) to force Defender into the path-based pipeline.

### 3.4 The Re-Verification Gate

When MsMpEng.exe performs path-based quarantine (Cloud Files path), it implements a re-verification gate before signaling Layer 1 for destructive action:

```
Re-Verification Sequence (observed in ProcMon):
─────────────────────────────────────────────────
1. CreateFile       → open file at resolved path
2. ReadFile         → read 16 bytes (signature header check)
3. FSCTL_READ_FILE_USN_DATA → get USN journal data
4. QueryIdInformation → get NTFS File ID
5. Compare File ID + USN against original detection record
6. If MATCH → proceed to quarantine
7. If MISMATCH → ABORT (no signal to WdFilter)
```

This gate is **identity-based, not content-based**. Placing identical malicious content at the junction target does NOT bypass the gate because the target file has a different NTFS File ID. File IDs are immutable per-file — assigned by NTFS at creation time and never changed.

### 3.5 Handle-Aware Quarantine Deferral

WdFilter implements handle-aware quarantine deferral:

- When EICAR is detected via inline scan (`IRP_MJ_WRITE`), WdFilter flags the file
- If any handle remains open (`FILE_SHARE_READ|WRITE|DELETE`), quarantine is deferred
- Quarantine executes only after the last handle is closed (`IRP_MJ_CLEANUP`)
- This prevents data loss from quarantining files while applications are actively using them

This has implications for exploit development: holding a file handle open prevents quarantine but also prevents the oplock-based notification that published exploits rely on for timing.

### 3.6 Cloud Files Data Delivery (CfExecute)

The Cloud Files data delivery function (`CfExecute`) writes hydrated data to disk through a `FILE_OBJECT` reference, not through path resolution:

- CfExecute operates below ProcMon's minifilter altitude
- It uses the FILE_OBJECT captured at placeholder creation time
- If the original file is deleted and replaced with a junction, CfExecute returns `ERROR_FILE_NOT_FOUND` (0x80070002)
- CfExecute data delivery is junction-immune

```
Minifilter Altitude Stack:
────────────────────────────
ProcMon          ~385000  (observation)
WdFilter         ~328010  (AV scan)
cldflt.sys       ~180451  (Cloud Files hydration)
                          ↑ CfExecute writes happen here
                            below both ProcMon and WdFilter
```

### 3.7 Extension Probe Search

During quarantine, MsMpEng.exe searches for related files by probing multiple extensions at the target path:

```
Probed extensions (observed):
.exe  .dll  .lnk  .cmd  .bat  .com  .pif
```

This is a quarantine completeness mechanism — when Defender quarantines a threat, it checks for companion files with different extensions that might be part of the same threat family.

---

## 4. Key Findings

### Finding 1 — WdFilter Scan-on-Write

WdFilter scans files inline on `IRP_MJ_WRITE`, not just on handle close (`IRP_MJ_CLEANUP`). Files flagged during write are cached in WdFilter's internal database. Subsequent `CreateFile` calls on flagged files return `ERROR_VIRUS_INFECTED` (225) immediately — before NTFS even processes the request.

**Defensive significance:** This is more aggressive than the commonly documented "scan-on-close" behavior. It prevents TOCTOU attacks that rely on writing malicious content and then racing to open a second handle.

### Finding 2 — Oplock FILE_OBJECT Semantics

Batch oplock compatibility is evaluated per-FILE_OBJECT, not per-process. Each `CreateFile` call creates a new FILE_OBJECT in the kernel's I/O subsystem. A single-threaded process cannot open a second handle to an oplock-held file without deadlocking — the thread would need to both wait for the oplock acknowledgment AND provide the acknowledgment.

**Defensive significance:** This makes single-threaded oplock-based TOCTOU exploits impossible. Multi-threaded designs are required, increasing complexity and reducing reliability.

### Finding 3 — Handle-Aware Quarantine Deferral

MsMpEng.exe does not forcefully quarantine files while application handles are open. The quarantine action is deferred until `IRP_MJ_CLEANUP` fires (all handles closed). This creates a catch-22 for oplock-based attacks: keeping a handle open prevents quarantine; closing it removes the timing notification.

**Defensive significance:** Legitimate applications are protected from having files ripped out from under them. The deferral also breaks a class of oplock-based timing attacks.

### Finding 4 — Cached FILE_OBJECT Quarantine (Regular Files)

For regular files, Defender's quarantine pipeline operates entirely through cached FILE_OBJECT references. Zero path operations from MsMpEng.exe appear in ProcMon during quarantine. The FILE_OBJECT is a direct kernel pointer to the physical file — path resolution (and therefore junction traversal) never occurs.

**Defensive significance:** Regular file quarantine is architecturally immune to junction-based attacks. The path namespace is never consulted.

### Finding 5 — Cloud Files Force Path-Based Quarantine

Cloud Files placeholders trigger a fundamentally different quarantine code path. MsMpEng.exe issues 28+ `CreateFile` calls by path during quarantine of placeholder files. All of these calls traverse the NTFS namespace and follow junctions (evidenced by `REPARSE` → `SUCCESS` in ProcMon).

**Defensive significance:** The Cloud Files quarantine path IS vulnerable to junction traversal. This is mitigated by Findings 6 and 7 (re-verification gate and kernel-layer delete).

### Finding 6 — Identity-Based Re-Verification Gate

The path-based quarantine pipeline re-verifies file identity before destructive action. It compares:
- NTFS File ID (via `QueryIdInformation`)
- USN journal data (via `FSCTL_READ_FILE_USN_DATA`)

against the original detection record. File IDs are immutable per-file (assigned at NTFS creation time). Any identity mismatch causes the quarantine to ABORT — no signal is sent to WdFilter for deletion.

**Defensive significance:** Even when junction traversal succeeds (Finding 5), the identity gate prevents the traversal from resulting in file deletion. Content matching is insufficient — the physical file identity must match.

### Finding 7 — WdFilter Kernel-Layer Delete

The actual quarantine deletion is performed by WdFilter.sys through cached FILE_OBJECT references. Zero `SetDispositionInformationFile` calls appear from MsMpEng.exe in the entire ProcMon trace (481 events analyzed). MsMpEng.exe's path-based pipeline is purely investigative.

**Defensive significance:** The destructive operation (delete) uses a junction-immune mechanism regardless of what happens in the path-based pipeline. This is the strongest defense-in-depth layer.

### Finding 8 — CfExecute is FILE_OBJECT-Based

Cloud Files data delivery (`CfExecute`) uses FILE_OBJECT references for disk writes. If the original placeholder file is deleted and replaced with a junction during the hydration callback, CfExecute returns `ERROR_FILE_NOT_FOUND`. It does not follow junctions.

**Defensive significance:** The hydration write mechanism cannot be redirected through junctions. Write-primitive attacks via CfExecute are architecturally blocked.

### Finding 9 — SYSTEM Read Primitive Through Junction

MsMpEng.exe (running as SYSTEM) reads file content at the junction-resolved path during re-verification. This read succeeds even though quarantine ultimately aborts. The SYSTEM-level `ReadFile` (16 bytes observed) operates on the target file through the attacker-created junction.

**Defensive significance:** This constitutes a defense-in-depth boundary violation. A standard user can force a SYSTEM-privileged process to read arbitrary files by controlling the junction target. The read is limited (16-byte header check) but confirms SYSTEM-level file access through user-created junctions.

### Finding 10 — User Impersonation During Quarantine

Some quarantine operations are performed under the identity of the triggering user (`Impersonating: <username>`), not under the SYSTEM identity. This is observed in ProcMon's detail column for certain `CreateFile` calls during the path-based quarantine pipeline.

**Defensive significance:** Impersonation means some quarantine access checks are bounded by user-level permissions. However, non-impersonated operations still run as SYSTEM.

### Finding 11 — 5-Second Quarantine Gap

For Cloud Files placeholders, the gap between scan completion and quarantine start is approximately 5 seconds (observed: 5.0s across multiple engagements). Junction swap operations complete in <1ms. This creates a timing margin of approximately 5000x.

**Defensive significance:** The gap is large enough that TOCTOU junction swaps are not a "race" but a "walk." Any defense relying on the swap being too slow to execute is ineffective.

### Finding 12 — Custom Scan Uses Path-Based Delete

Custom scans triggered via `MpCmdRun.exe -Scan -ScanType 3 -File <path>` use a fundamentally different quarantine mechanism than Real-Time Protection. The custom scan pipeline issues `SetDispositionInformationFile` directly from MsMpEng.exe — a **path-based delete** from user-mode code.

This operation was observed at ProcMon line 383 of a 505-event trace (custom scan quarantine of a baseline file with no junction):

```
"MsMpEng.exe","SetDispositionInformationFile","...\bait.exe","SUCCESS","Delete: True"
```

In contrast, RTP quarantine shows **zero** `SetDispositionInformationFile` across 481+ analyzed events. RTP deletes exclusively through WdFilter.sys cached FILE_OBJECT references.

**Three distinct quarantine architectures identified:**

| Scan Type | Delete Mechanism | Path Operations? | Junction-Vulnerable? |
|-----------|-----------------|-------------------|---------------------|
| RTP (regular files) | WdFilter FILE_OBJECT | None | No (immune) |
| RTP (Cloud Files) | WdFilter after MsMpEng verify | Verify only | Verify follows junction, delete doesn't |
| Custom scan | MsMpEng SetDispositionInformationFile | **Full pipeline + delete** | Delete is path-based (mitigated by Findings 13-14) |

**Defensive significance:** The custom scan pathway has a wider attack surface than RTP. A standard user can trigger custom scans via `MpCmdRun.exe` without administrator privileges. The path-based delete is architecturally capable of following junction redirects, though additional defenses (Findings 13, 14) currently prevent this.

### Finding 13 — Reparse Point Awareness in Custom Scan

During custom scan quarantine, MsMpEng.exe explicitly opens directories with the `Open Reparse Point` flag and checks `FileAttributes` for the `DRP` (Directory + Reparse Point) flag. When a junction is detected:

```
Line 406: CreateFile vader_jnx  → SUCCESS (Options: Open Reparse Point)
Line 407: QueryNetworkOpenInfo  → FileAttributes: DRP
```

MsMpEng performs this check **twice** per quarantine cycle. When `DRP` is detected, the quarantine pipeline completes its full investigation (content read, identity verification) but **does not fire** `SetDispositionInformationFile`. The delete is suppressed.

This is a **separate defense** from the identity-based re-verification gate (Finding 6). Even if file identity matched, the DRP detection appears to independently abort the quarantine.

**Defensive significance:** MsMpEng has explicit junction awareness in the custom scan path. The reparse point attribute check provides a second line of defense beyond file identity verification. This was not documented in prior research.

### Finding 14 — SYSTEM Read Primitive via Custom Scan

MsMpEng.exe (running as SYSTEM) reads file content through junctions during custom scan quarantine, even when the quarantine ultimately aborts:

```
Line 433: ReadFile vader_target\bait.exe → SUCCESS, Offset: 0, Length: 68
Line 472: ReadFile vader_target\bait.exe → SUCCESS, Offset: 0, Length: 68
```

Two complete 68-byte reads (full EICAR content) occur through the junction-resolved path, at SYSTEM privilege level. This extends Finding 9 (SYSTEM read primitive discovered in Cloud Files quarantine) to the custom scan pathway.

The custom scan read is 68 bytes versus 16 bytes observed in Cloud Files quarantine — MsMpEng reads the full file content in custom scan mode, not just the signature header.

**Defensive significance:** The SYSTEM read primitive exists across both Cloud Files and custom scan quarantine pathways. A standard user can trigger either pathway to force SYSTEM-privileged file reads through user-controlled junctions. The custom scan pathway is particularly accessible since it requires only `MpCmdRun.exe` (no Cloud Files registration).

### Finding 15 — Volume Shadow Copy Access in Custom Scan

During custom scan quarantine, MsMpEng.exe reads files from `\Device\HarddiskVolumeShadowCopy1\` — the Volume Shadow Copy Service:

```
Line 311: CreateFile \Device\HarddiskVolumeShadowCopy1\...\bait.exe → SUCCESS
```

This VSS access was **not observed** in any RTP trace. MsMpEng appears to cross-reference the file's historical state (VSS snapshot) against its current state during custom scan quarantine.

**Defensive significance:** This reveals an additional verification step in the custom scan pipeline. VSS cross-referencing may provide temporal integrity checking — comparing the file's current state against a point-in-time snapshot to detect tampering.

### Finding 16 — Handle Deferral Blocks Quarantine via SHARING_VIOLATION

When a user-mode process holds a handle on a detected file with `FILE_SHARE_READ` only (no `FILE_SHARE_DELETE`), MsMpEng.exe's quarantine pipeline is blocked at the `CreateFile` stage. MsMpEng attempts multiple access patterns, all returning `SHARING_VIOLATION`:

```
Line 305: CreateFile → SHARING VIOLATION  (Desired Access: Read Attributes, Write Attributes, Delete)
Line 306: CreateFile → SHARING VIOLATION  (Desired Access: Generic Read/Write, ShareMode: None)
Line 339: CreateFile → SHARING VIOLATION  (Desired Access: Generic Read/Write, ShareMode: None)
Line 348: CreateFile → SHARING VIOLATION  (Desired Access: Read Data, ShareMode: Write)
Line 349: CreateFile → SHARING VIOLATION  (Desired Access: Read Data, ShareMode: Write, Impersonating: user)
```

MsMpEng cycles through **five distinct access patterns** including user impersonation before giving up. Meanwhile, read-only access continues to succeed — the custom scan scanner (MpCmdRun) can still read and detect the file, returning exit code 2 (threat found).

**Defensive significance:** Handle deferral is a real defense mechanism (Finding 3), but this reveals the specific failure modes. A user-mode process can prevent SYSTEM quarantine of its own files by holding a restrictive handle. This is by design — legitimate applications should not have files ripped out from under them. However, it also means an attacker can create a detection record while preventing remediation.

### Finding 17 — DRP Check Bypass via TOCTOU Timing

The reparse point awareness defense (Finding 13) checks the staging directory BEFORE the junction exists. During handle-deferred quarantine, the DRP check fires while the handle blocks quarantine:

```
Line 124: FSCTL_GET_REPARSE_POINT → NOT REPARSE POINT  (during scan, before swap)
Line 132: FSCTL_GET_REPARSE_POINT → NOT REPARSE POINT
Line 146: FSCTL_GET_REPARSE_POINT → NOT REPARSE POINT
Line 154: FSCTL_GET_REPARSE_POINT → NOT REPARSE POINT
...
(12+ DRP checks, ALL return NOT REPARSE POINT — junction not yet planted)
```

The DRP check result is consumed during the scan phase. When the junction is planted after handle release, the DRP check does **not re-fire**. This confirms that the DRP defense is vulnerable to its own TOCTOU: if the directory is normal at check-time but becomes a junction at quarantine-time, the check is bypassed.

**Defensive significance:** The DRP check (Finding 13) is a verification-based defense, not an architectural one. It can be bypassed with correct timing — checking happens during investigation, not at the moment of `SetDispositionInformationFile`. This narrows the remaining defense to the identity gate (Finding 6) alone.

### Finding 18 — Fail-and-Forget Quarantine Model

When MsMpEng's quarantine fails with SHARING_VIOLATION, the quarantine action is **consumed, not deferred**. After five failed access attempts, MsMpEng abandons the quarantine entirely. No retry mechanism fires after the blocking handle is released.

Empirical evidence: ProcMon monitoring for 90 seconds after handle release showed **zero** MsMpEng activity on the staging path. The detection record exists (exit code 2 confirmed threat), the junction is in place, the target is accessible — but MsMpEng never returns.

```
Timeline:
  9:58:36.573  Last SHARING_VIOLATION (attempt 5 of 5)
  9:58:37.177  Last MsMpEng activity on staging path (oplock + read)
  9:58:37.2+   Handle released, junction planted (8.13ms swap)
  9:58:37 - 10:00:07  90-second monitoring → ZERO activity
```

This is distinct from Finding 3 (handle-aware deferral). Finding 3 describes quarantine being **deferred** while handles are open. Finding 18 reveals that after explicit SHARING_VIOLATION failures, the quarantine is **abandoned** — the retry logic does not queue a re-attempt for when the handle is eventually released.

**Defensive significance:** The fail-and-forget model prevents an attacker from using handle deferral to time a junction swap. However, it also means that detected threats may remain on disk indefinitely if quarantine fails — a potential gap in remediation completeness. The attacker's challenge shifts from "racing the retry" to "forcing a re-remediation attempt through an already-planted junction."

---

## 5. Primitive Analysis

### 5.1 What an Attacker Can Achieve

| Primitive | Status | Mechanism | Severity |
|-----------|--------|-----------|----------|
| SYSTEM file read (Cloud Files) | Confirmed | MsMpEng reads 16 bytes through junction during re-verification | Medium |
| SYSTEM file read (Custom Scan) | Confirmed | MsMpEng reads 68 bytes (full content) through junction | Medium |
| SYSTEM FSCTL operations | Confirmed | Oplock requests, USN queries through junction | Low |
| Access time oracle | Confirmed | LastAccessTime modified on target files | Low |
| Oplock disruption | Confirmed | SYSTEM breaks existing oplocks through junction | Low |
| SYSTEM file delete (RTP) | Blocked | WdFilter uses FILE_OBJECT (junction-immune) + identity gate | N/A |
| SYSTEM file delete (Custom Scan) | Blocked | SetDispositionInformationFile exists but identity gate aborts | N/A |
| Handle-deferred quarantine bypass | Blocked | Fail-and-forget model — no retry after SHARING_VIOLATION | N/A |
| DRP check bypass (TOCTOU timing) | **Confirmed** | DRP checks fire during scan, not at delete time — bypassable | Medium |
| SYSTEM file write | Blocked | CfExecute uses FILE_OBJECT (junction-immune) | N/A |

### 5.2 Why the Dangerous Primitives Are Blocked

**Delete (RTP):** Two independent layers prevent it:
1. The identity-based re-verification gate (Layer 2) aborts on File ID mismatch
2. Even if the gate passed, WdFilter (Layer 1) deletes through FILE_OBJECT, not path

**Delete (Custom Scan):** One confirmed defense prevents it:
1. The identity-based re-verification gate (Finding 6) provides an abort condition on File ID mismatch
Note: The DRP check (Finding 13) has been confirmed bypassable via TOCTOU timing (Finding 17) — the check fires during scan, not at delete time. The identity gate is now the **sole remaining defense** against junction-redirected deletion in the custom scan pipeline. Unlike RTP (where the delete mechanism itself is junction-immune), custom scan's `SetDispositionInformationFile` IS path-based and WOULD follow junctions if the identity gate were bypassed.

**Write:** CfExecute (Cloud Files data delivery) operates through FILE_OBJECT references. Path resolution never occurs during data delivery. The write happens at minifilter altitude ~180451, below both ProcMon (~385000) and WdFilter (~328010).

### 5.3 Defense-in-Depth Assessment

The quarantine pipeline implements effective defense-in-depth across three distinct architectures:

```
Attack Attempt              Defense Layer(s)                              Result
─────────────────────────   ───────────────────────────────────────────   ──────
Regular file + junction     WdFilter FILE_OBJECT (junction-immune)        BLOCKED
Cloud File + junction       FILE_OBJECT delete + identity gate            BLOCKED*
Custom scan + junction      Identity gate (DRP bypassed via TOCTOU)       BLOCKED**
Handle-deferred + swap      Fail-and-forget (no retry after SHARING_VIOLATION)  BLOCKED***
CfExecute write redirect    FILE_OBJECT (junction-immune)                 BLOCKED

* Junction followed during verify, but FILE_OBJECT delete is immune
** DRP check bypassed (Finding 17), identity gate is SOLE remaining defense
*** Detection exists, junction in place, but quarantine never retries (Finding 18)
```

The custom scan pathway represents the narrowest defense margin. Unlike RTP (where the delete mechanism itself is junction-immune), custom scan's `SetDispositionInformationFile` IS path-based and WOULD follow junctions if the reparse point awareness check and identity gate were both bypassed. The defense relies entirely on pre-delete verification rather than architectural immunity.

---

## 6. Defensive Recommendations

### 6.1 For System Administrators

1. **Monitor junction creation in sensitive directories.** Standard users can create NTFS junctions in any directory they own. Sysmon Event ID 11 (FileCreate) with `ReparseTarget` field can detect junction creation. Focus monitoring on `%TEMP%`, `%USERPROFILE%`, and any directories where Cloud Files sync roots are registered.

2. **Restrict Cloud Files sync root registration.** The Cloud Files API allows standard users to register sync roots. Consider Group Policy or application control policies to restrict which applications can call `CfRegisterSyncRoot`.

3. **Monitor Defender quarantine anomalies.** When quarantine aborts with an identity mismatch, this may indicate a junction-based attack attempt. Defender event logs (Event ID 1116 for detection, 1117 for action) can be correlated with junction creation events.

4. **Audit directory permissions in SYSTEM-writable paths.** The junction-based SYSTEM read primitive allows a standard user to force MsMpEng.exe to read files in any SYSTEM-accessible directory. Ensure that sensitive files have explicit DACL entries rather than relying on inherited permissions.

### 6.2 For Security Researchers

1. **The Cloud Files path is the attack surface.** Regular file quarantine is junction-immune. Research should focus on mechanisms that force path-based operations in Defender's pipeline — Cloud Files placeholders, virtual disk mounts, or any filesystem mechanism that prevents FILE_OBJECT caching.

2. **Identity checks are the LAST gate.** As of v9, the DRP check is confirmed bypassable via TOCTOU timing (Finding 17). File ID is immutable per-file. The identity gate (Finding 6) is now the sole defense preventing junction-redirected deletion in custom scan quarantine. Bypassing it requires either finding a code path that skips identity checks, finding a way to influence NTFS File ID assignment, or finding a trigger that forces re-remediation without identity verification (none observed in this research).

3. **Custom scan quarantine is the weakest architecture.** Custom scan quarantine uses path-based `SetDispositionInformationFile` — unlike RTP which is architecturally junction-immune via FILE_OBJECT. The DRP check is bypassable (Finding 17). The fail-and-forget model (Finding 18) prevents handle-deferred timing attacks. The remaining attack surface is: find a mechanism to trigger quarantine on a stored detection record through a junction path, bypassing or satisfying the identity gate. Vectors to test: forced re-remediation via MpCmdRun/PowerShell, scheduled scan re-processing of unresolved detections, different detection types (PUA, behavioral, script-based) that may share the pipeline but skip identity verification.

4. **The fail-and-forget model has a remediation gap.** Finding 18 shows MsMpEng abandons quarantine after SHARING_VIOLATION without scheduling a retry. Detected threats may persist on disk. This is worth investigating from a defensive completeness perspective — does Defender's periodic maintenance eventually re-process these detections?

### 6.3 For Microsoft

This research was disclosed to MSRC as a defense-in-depth finding. Specific recommendations:

1. **Consider eliminating path-based operations in the Cloud Files quarantine pipeline.** The divergence between regular-file (FILE_OBJECT) and Cloud-Files (path-based) quarantine creates an unnecessary attack surface.

2. **The SYSTEM read primitive through junctions constitutes an information disclosure boundary violation.** While limited (16-byte reads observed), the principle — standard user forcing SYSTEM-level reads on arbitrary paths — may have broader implications.

3. **The 5-second quarantine gap for Cloud Files is unnecessarily large.** A 5000x timing margin makes junction swaps trivial. Reducing this gap would increase the difficulty of TOCTOU attacks, though the identity gate remains the primary defense.

---

## 7. Responsible Disclosure

| Date | Action |
|------|--------|
| 2026-06-13 | Research initiated. Cloud Files path-based quarantine discovered. |
| 2026-06-13 | Junction traversal confirmed. SYSTEM read primitive verified. |
| 2026-06-14 | Dual-layer architecture fully mapped. RTP DELETE/WRITE primitives confirmed dead. |
| 2026-06-14 | v8b: Custom scan quarantine discovered to use path-based SetDispositionInformationFile. Three distinct quarantine architectures documented. Reparse point awareness defense identified. |
| 2026-06-14 | v8c-fix: Handle deferral confirmed — FILE_SHARE_READ blocks quarantine with SHARING_VIOLATION. DRP check bypass via TOCTOU timing confirmed (Finding 17). |
| 2026-06-14 | v9: Full handle-deferred custom scan test. MsMpEng hit 5 SHARING_VIOLATIONs, abandoned quarantine permanently. Fail-and-forget model documented (Finding 18). |
| 2026-06-14 | MSRC disclosure prepared (defense-in-depth finding: SYSTEM junction traversal with read primitive, path-based delete in custom scan, DRP bypass confirmed, identity gate is sole remaining defense). |

**Disclosure policy:** This research follows coordinated disclosure practices. Architecture documentation is published for defensive purposes. No exploit code is included in this repository.

---

## 8. Forward Application: What the Architecture Taught Us

This research produced zero exploitable privilege escalation against WdFilter's quarantine pipeline. That's the point. A thorough negative result has its own value — it maps the defense surface precisely enough to inform where to look next.

### 8.1 Why WdFilter Held

The dual-layer architecture (kernel FILE_OBJECT caching + user-mode identity gate) is genuinely robust against junction-based TOCTOU. Key lessons:

- **FILE_OBJECT caching makes junctions invisible at quarantine time** (Finding 4). The kernel already has a handle to the real file. The junction is a path-layer redirect; WdFilter operates at the object layer. Architecture, not patches.
- **Identity gate uses NTFS File ID** (Finding 6). Immutable per-file. Not spoofable via junctions, not affected by renames, not dependent on path resolution. The gate is a single comparison, and it's architecturally correct.
- **CfExecute is also FILE_OBJECT-based** (Finding 8). Even the Cloud Files path, which forces path-based quarantine, still performs the critical operations through cached handles.

### 8.2 Where the Seams Are

What the research DID reveal about the broader minifilter ecosystem:

- **cldflt.sys (altitude 180451) sits below WdFilter (altitude 328010) in the minifilter stack.** Operations that WdFilter scrutinises never reach cldflt in the same inspection pass. This altitude gap means Cloud Files operations interact with the kernel at a layer WdFilter doesn't monitor during quarantine.
- **The CfAbortHydration callback path** (observed during Cloud Files placeholder interactions) involves token impersonation during kernel-mode callbacks. This is the race surface that MiniPlasma demonstrated — not against WdFilter, but against cldflt itself.
- **The 5-second quarantine gap** (Finding 11) demonstrates that even well-defended pipelines have timing windows. The gap's irrelevance to WdFilter (identity gate catches everything) doesn't mean it's irrelevant to other minifilters in the stack.

### 8.3 Minifilter Altitude Stack (Observed)

```
                   ALTITUDE
ProcMon      ~385,000   (observation layer)
WdFilter      328,010   (Defender real-time protection)
bindflt       409,800   (Bind Filter — AppX VFS)
cldflt        180,451   (Cloud Files Mini-Filter)
NTFS          100,000   (filesystem)
```

The research on WdFilter's architecture directly informed the pivot to cldflt/bindflt research. The quarantine pipeline is hardened. The minifilter stack beneath it is less studied.

### 8.4 Research Continuity

| Phase | Focus | Outcome |
|-------|-------|---------|
| **vader-toctou** (this research) | WdFilter quarantine architecture | 18 findings. Wall held. Architecture mapped. |
| **Rootkit phase** | Service ACLs, PATH injection, Defender telemetry | 22+ findings. SYSTEM achieved (third-party). CVE submissions prepared. |
| **VADER-PRIME** | cldflt race + novel payload chains | Framework compiled. Untested. Depends on race viability on current build. |

The quarantine architecture research is the foundation. Every subsequent finding was informed by understanding where WdFilter looks — and where it doesn't.

---

## 9. References

- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [EICAR Anti-Malware Test File](https://www.eicar.org/download-anti-malware-testfile/)
- [Microsoft: Windows Minifilter Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)
- [Microsoft: Cloud Files API](https://learn.microsoft.com/en-us/windows/win32/cfapi/cloud-files-api-portal)
- [Microsoft: NTFS Reparse Points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
- [Microsoft: Opportunistic Locks](https://learn.microsoft.com/en-us/windows/win32/fileio/opportunistic-locks)
- [Sysinternals: Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

---

## Author

**George Wu** — Independent security researcher, Sydney, Australia.
Cybersecurity student (CSEC).  GitHub: [rainfantry](https://github.com/rainfantry).

Portfolio: [rainfantry.github.io](https://rainfantry.github.io)

This research was conducted as part of academic cybersecurity coursework on personally-owned hardware. No unauthorized systems were accessed or targeted. Responsible disclosure via MSRC for all Microsoft-actionable findings.

---

## License

MIT License. See [LICENSE](LICENSE).

---
