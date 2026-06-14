# ProcMon Analysis Reference

**Author:** George Wu (22DIV)

This document explains the specific ProcMon operations observed during Defender quarantine events and what they reveal about internal architecture.

---

## Filtering

All ProcMon captures used:
- **Process Name is** `MsMpEng.exe`
- **Path contains** the test directory name (e.g., `vader_staging`, `vader_target`)

Category filter: Filesystem operations only (Registry and Network excluded).

---

## Key Operations Observed

### CreateFile

MsMpEng.exe opens files during quarantine investigation. Multiple access patterns observed:

| Desired Access | Purpose | Typical Count |
|---------------|---------|---------------|
| Generic Read | Content re-verification (scan content at resolved path) | 3-5 per burst |
| Read Attributes | Metadata queries (size, timestamps, attributes) | 5-10 per burst |
| Read Data/List Directory | Directory enumeration for extension probes | 2-4 per burst |

**Impersonation:** Some CreateFile calls appear with `Impersonating: <username>` in ProcMon's detail column. MsMpEng.exe drops from SYSTEM context to the triggering user's identity for access checks. This bounds certain operations to user-level permissions.

### REPARSE Result

When a CreateFile path contains an NTFS junction, ProcMon shows:

```
CreateFile    C:\...\vader_jnx\bait.exe    REPARSE    ...
CreateFile    C:\...\vader_target\bait.exe  SUCCESS    ...
```

The `REPARSE` result indicates the filesystem encountered a reparse point (junction). The subsequent `SUCCESS` on the resolved path confirms the junction was followed. This pair is the definitive evidence of junction traversal.

### ReadFile

```
ReadFile    C:\...\bait.exe    SUCCESS    Offset: 0, Length: 16
```

16-byte reads at offset 0 are signature header checks — MsMpEng reads enough data to verify the file type/content matches the original detection. The 16-byte read through a junction constitutes the SYSTEM read primitive.

Full 68-byte reads (matching EICAR size) indicate a complete content scan.

### FSCTL_READ_FILE_USN_DATA

```
FSCTL_READ_FILE_USN_DATA    C:\...\bait.exe    SUCCESS
```

Queries the USN (Update Sequence Number) journal data for the file. USN data includes:
- USN record number (changes with each modification)
- Reason flags (what changed)
- Timestamp
- File reference number (contains the 64-bit NTFS File ID)

MsMpEng.exe uses this to verify file identity against the original detection record.

### QueryIdInformation

```
QueryIdInformation    C:\...\bait.exe    SUCCESS
```

Retrieves the NTFS File ID — a 64-bit identifier unique to each file on the volume. File IDs are:
- Assigned at file creation by NTFS
- Immutable for the lifetime of the file
- Unique per volume (no two files share a File ID)
- Not the same as the filename or path

This is the identity gate: MsMpEng compares the target file's ID against the ID recorded during initial detection.

### FSCTL_REQUEST_OPLOCK

```
FSCTL_REQUEST_OPLOCK    C:\...\bait.exe    OPLOCK HANDLE CLOSED
```

MsMpEng.exe requests an opportunistic lock during quarantine investigation. The `OPLOCK HANDLE CLOSED` result indicates the oplock was granted and then released within the same operation sequence. This is a defensive lock — MsMpEng briefly locks the file to prevent modifications during its investigation.

### QueryStreamInformationFile

```
QueryStreamInformationFile    C:\...\bait.exe    SUCCESS
```

Checks for alternate data streams (ADS) on the file. NTFS files can have multiple named streams (e.g., `file.exe:Zone.Identifier`). Defender checks for threat content hidden in alternate streams.

### QueryEaFile

```
QueryEaFile    C:\...\bait.exe    SUCCESS / NO EAS ON FILE
```

Checks for Extended Attributes. Rarely used in modern Windows but some legacy applications and the Cloud Files minifilter use EAs for metadata.

### NAME NOT FOUND / PATH NOT FOUND

```
CreateFile    C:\...\bait.exe    NAME NOT FOUND
CreateFile    C:\...\bait.dll    NAME NOT FOUND
CreateFile    C:\...\bait.lnk    NAME NOT FOUND
```

Extension probe search. After quarantining a file, MsMpEng searches for companion files with different extensions. All probed extensions observed:

`.exe` `.dll` `.lnk` `.cmd` `.bat` `.com` `.pif`

### FILE_LOCKED_WITH_ONLY_READERS

```
CreateFile    C:\...\bait.exe    FILE LOCKED WITH ONLY READERS
```

The file is currently open by another process (or another MsMpEng thread) with read-only access. MsMpEng must wait or retry. This typically appears during the quarantine deferral window when the test program's handle is still open.

---

## What's Missing: SetDispositionInformationFile

The most significant observation is what does NOT appear:

**Zero `SetDispositionInformationFile` operations in the entire 481-event trace.**

`SetDispositionInformationFile` is the Win32 API path to file deletion. If MsMpEng.exe were performing the quarantine delete itself, this operation would appear. Its absence proves that:

1. MsMpEng.exe's path-based pipeline is purely investigative
2. The actual delete is performed by a different component (WdFilter.sys)
3. WdFilter.sys operates through cached FILE_OBJECT references, not through the path namespace

This is the key evidence for the dual-layer architecture: the component that follows junctions (MsMpEng) never deletes, and the component that deletes (WdFilter) never follows junctions.

---

## Quarantine Burst Anatomy

A typical Cloud Files quarantine event produces 40-100+ ProcMon events in a structured burst:

```
Phase 1 — File Access (CreateFile)
  ├── Open for read access
  ├── Possible REPARSE if junction present
  └── Possible impersonation

Phase 2 — Content Verification (ReadFile)
  ├── 16-byte header check
  └── Optional full content scan

Phase 3 — Identity Verification (FSCTL + Query)
  ├── FSCTL_READ_FILE_USN_DATA
  ├── QueryIdInformation
  └── Compare against detection record

Phase 4 — Metadata Collection
  ├── QueryStreamInformationFile
  ├── QueryEaFile
  └── FSCTL_REQUEST_OPLOCK (defensive lock)

Phase 5 — Decision
  ├── Identity MATCH → signal WdFilter for quarantine
  └── Identity MISMATCH → ABORT (close handles, no quarantine)

Phase 6 — Extension Probes (post-quarantine)
  ├── CreateFile(bait.dll) → NAME NOT FOUND
  ├── CreateFile(bait.lnk) → NAME NOT FOUND
  └── ... (7 extensions probed)
```

---

## Minifilter Altitude Stack

Understanding the minifilter altitude hierarchy explains why certain operations are visible or invisible in ProcMon:

```
Altitude    Component        Role
────────    ──────────       ────
~385000     ProcMon          Observation (Sysinternals filter)
~328010     WdFilter.sys     Defender scan + quarantine
~180451     cldflt.sys       Cloud Files hydration
~100000     NTFS             Filesystem driver
```

Operations performed by components BELOW ProcMon's altitude appear in the trace. Operations performed at or below cldflt.sys altitude (such as CfExecute disk writes) are invisible to ProcMon.

WdFilter's quarantine delete operations are also invisible when performed through cached FILE_OBJECT references because they bypass the path-based I/O stack that ProcMon monitors. ProcMon sees named-path operations; FILE_OBJECT operations go directly to the filesystem driver.
