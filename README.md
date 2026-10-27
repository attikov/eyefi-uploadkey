# Eye-Fi Diagnostic Utility

A standalone Python utility for reading existing diagnostic dumps from Eye-Fi SD cards and locating their stored authentication keys. It uses Python's standard library; no separate EXE, Eye-Fi utility or Python package installation is required.

This project is not affiliated with or endorsed by Eye-Fi. Use it only on cards you own or are authorized to examine.

## What has been verified

The tool was tested on one Eye-Fi X2 card running firmware **4.5166**. Existing dumps were read over USB, the stored keys were recovered, and one recovered key was successfully used for real photo uploads to a local NAS receiver.

This is not evidence that every Eye-Fi or X2 card has the same firmware, dump layout or key selection. The defaults follow the analyzed 4.5166 firmware: dump slots **1 through 3**, each **327,680 bytes (320 KiB)**.

The tool reads diagnostics and reports keys. It does not configure Wi-Fi, register or activate a card, install firmware, or receive photos.

## Requirements

- Python 3; tested with Python 3.14 on Windows.
- Windows for direct access to a card in a USB SD-card reader.
- The card's existing `EYEFI` directory containing `REQM`, `REQC`, `RSPM` and `RSPC`.

Offline extraction from an existing dump does not use the Windows APIs and can also be run on other operating systems.

Close other Eye-Fi configuration programs before accessing the card so they do not use the same request channel concurrently. Select the actual drive letter of the card; `X:` below is an example.

## Quick start

Open a terminal in the directory containing `eyefi_diagnostic.py` and run:

```powershell
python eyefi_diagnostic.py X:
```

This is shorthand for `scan X:`. It reads slots 1 through 3, saves their response ranges into a new timestamped directory beside the script, and searches for board-data records. You do not need to know the MAC address or dump number first.

For each matching record, it prints:

- The record's offset within the saved range.
- The MAC address stored in that record.
- The key at board-data offset `+0x20`.
- The key at board-data offset `+0x40`.

Both keys are reported without choosing which one is active. On the tested card in Desktop mode, the key at `+0x40` worked. The appropriate key on another card depends on its firmware and configuration.

The output directory contains `dump1.response.bin`, `dump2.response.bin`, `dump3.response.bin`, and `results.json`. The JSON includes both recovered key fields and scan status. Conflicting key pairs for the same MAC are reported rather than silently choosing one.

## Commands

### Scan the known dump slots

```powershell
python eyefi_diagnostic.py X:
```

Choose a new output directory:

```powershell
python eyefi_diagnostic.py scan X: --output-dir C:\EyeFiBackups\scan-001
```

An optional `--mac` filter accepts a plain hexadecimal MAC or one with colons or hyphens. `--first-index`, `--last-index` and `--bytes` allow explicit ranges for further investigation; they do not establish compatibility with another firmware version.

### Extract keys from a saved dump

```powershell
python eyefi_diagnostic.py extract C:\EyeFiBackups\scan-001\dump3.response.bin
```

### Read a particular dump range

```powershell
python eyefi_diagnostic.py read X: --dump-index 3 --bytes 327680 --output C:\EyeFiBackups\dump3.bin
```

`3` is the dump index, not a count of existing dumps. `--offset` selects a byte offset. Size must be positive; size and offset must be multiples of 16,384 bytes. If omitted for `read`, `--bytes` defaults to 1 MiB, which exceeds the verified dump size of this firmware; prefer the explicit size above.

### Read a card-log range

```powershell
python eyefi_diagnostic.py log X: --output C:\EyeFiBackups\card-log.bin
```

This reads the first 16 KiB of the log by default. Use `--offset` and `--bytes` to request other ranges. Logs can identify dump files, for example `/private/crshdump/dump3`.

### Explicit assertion/reset request: experimental

```powershell
python eyefi_diagnostic.py crash X:
```

**This command deliberately requests an assertion/reset. Its actual crash behavior has not been tested on a live card. Do not use it while the card is writing photos.**

The command:

1. Reads the reported firmware version and refuses versions other than 4.5166.
2. Saves and flushes response ranges for all three known dump slots into a new `eyefi-before-crash-*` directory. A backup I/O failure prevents the trigger.
3. Sends a single unsupported host command that static analysis traced to assertion handling, crash-state saving and reset in that firmware.
4. Records the request state in `crash-request.json` without claiming that a crash or new dump was confirmed.

A fresh dump can replace `dump3` when all slots are occupied. An I/O error during signalling can mean the card has already reset; the command does not retry. Once the card is accessible again, read its log and scan the dumps to establish what happened. A firmware version match alone is not a guarantee of safe or successful behavior.

Normal `scan`, `read`, `log` and `extract` commands do not deliberately trigger crashes. Running with just a drive letter always selects `scan`, never `crash`.

### Help

```powershell
python eyefi_diagnostic.py --help
python eyefi_diagnostic.py crash --help
```

## How it works and limitations

The card implements a host-control channel through four files. The host writes a request into `REQM`, signals a sequence number through `REQC`, and reads the acknowledgement and response from `RSPC` and `RSPM`. On Windows the utility uses aligned, uncached file access through `ctypes` to avoid stale filesystem cache data.

Command `k` requests a stored crash dump by index and byte offset; command `m` reads a log range. Key extraction looks for the board-data marker, MAC address and three adjacent 32-character hexadecimal fields, then reports the two authentication-key fields. Keys are recovered from the card's saved memory, not calculated from its MAC address.

The dump protocol has no verified file-listing, EOF or error status. An acknowledged request does not prove that a dump exists or that every requested byte belongs to it. Reads past the end can return repeated or stale data. The scanner preserves response ranges and marks entirely unchanged responses as unconfirmed; it does not treat those responses as recovered dumps. Files are named `.response.bin` to reflect this limitation.

The tool does not create missing request-channel files and does not overwrite existing local output files or directories. Local output must be on a different drive from the card. For `read` and `log`, the selected output file's parent directory must already exist. A card error can leave partial local output, which is retained for inspection.
