# EyeFi Diagnostic Utility
#
# Independent diagnostic utility for EyeFi SD cards.
#
# Intended for use only with devices owned by the user
# or devices the user is authorized to examine.
#
# This project is not affiliated with or endorsed by EyeFi.
#
# Diagnostic dumps and extracted authentication keys may
# contain sensitive information. Do not share them publicly.

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime
import json
import os
from pathlib import Path
import re
import struct
import sys
import time

BLOCK = 16384
BOARD_MARKER = bytes.fromhex("c0decafeaa526922")


class WindowsChannel:
    """Use page-aligned buffers and uncached IO, including on 64-bit Python."""

    def __init__(self, drive):
        if os.name != "nt":
            raise OSError("Reading a card requires Windows; extract works offline.")
        if not re.fullmatch(r"[a-zA-Z]:[\\/]?", drive):
            raise ValueError("Use a drive letter such as H:")
        self.root = Path(drive[:2] + "\\") / "EYEFI"
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        declarations = {
            "CreateFileW": ([wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                             wintypes.HANDLE], wintypes.HANDLE),
            "ReadFile": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
            "WriteFile": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                           ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
            "FlushFileBuffers": ([wintypes.HANDLE], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "VirtualAlloc": ([ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD,
                              wintypes.DWORD], ctypes.c_void_p),
            "VirtualFree": ([ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD], wintypes.BOOL),
        }
        for name, (arguments, result) in declarations.items():
            function = getattr(self.api, name)
            function.argtypes = arguments
            function.restype = result

    def transfer(self, name, data=None):
        if name not in {"REQM", "REQC", "RSPM", "RSPC"}:
            raise ValueError("Unknown diagnostic channel")
        write = data is not None
        if write and (name not in {"REQM", "REQC"} or len(data) != BLOCK):
            raise ValueError("Only complete request-channel blocks can be written")
        path = self.root / name
        access = 0x40000000 if write else 0x80000000
        flags = 0x20000000 | (0x80000000 if write else 0)
        # OPEN_EXISTING: never create a missing channel file.
        handle = self.api.CreateFileW(str(path), access, 7, None, 3, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        pointer = None
        try:
            pointer = self.api.VirtualAlloc(None, BLOCK, 0x3000, 4)
            if not pointer:
                raise ctypes.WinError(ctypes.get_last_error())
            if write:
                ctypes.memmove(pointer, data, BLOCK)
            done = wintypes.DWORD()
            operation = self.api.WriteFile if write else self.api.ReadFile
            if not operation(handle, pointer, BLOCK, ctypes.byref(done), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if done.value != BLOCK:
                raise OSError(f"Short channel transfer: {done.value}/{BLOCK}")
            if write and not self.api.FlushFileBuffers(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            return ctypes.string_at(pointer, BLOCK)
        finally:
            if pointer:
                self.api.VirtualFree(pointer, 0, 0x8000)
            self.api.CloseHandle(handle)

    def request(self, command, index=0, offset=0, timeout=20):
        if command not in {"k", "m"}:
            raise ValueError("Only dump/log read commands k/m are allowed")
        for value in (index, offset):
            if not 0 <= value <= 0xffffffff:
                raise ValueError("Index and offset must fit unsigned 32 bits")
        request = bytearray(BLOCK)
        request[0] = ord(command)
        if command == "k":
            struct.pack_into(">II", request, 1, index, offset)
        else:
            struct.pack_into(">I", request, 1, offset)
        sequence = (struct.unpack_from("<I", self.transfer("RSPC"))[0] + 1) & 0xffffffff
        self.transfer("REQM", bytes(request))
        control = bytearray(BLOCK)
        struct.pack_into("<I", control, 0, sequence)
        self.transfer("REQC", bytes(control))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if struct.unpack_from("<I", self.transfer("RSPC"))[0] == sequence:
                return self.transfer("RSPM")
            time.sleep(0.2)
        raise TimeoutError("Card did not acknowledge the diagnostic request")


def find_keys(data, mac=None):
    data = bytes(data)
    if mac:
        text = re.sub(r"[:-]", "", mac)
        if not re.fullmatch(r"[0-9a-fA-F]{12}", text):
            raise ValueError("MAC must contain exactly 12 hexadecimal digits")
        starts = [m.start() - 0x89 for m in re.finditer(re.escape(bytes.fromhex(text)), data)]
    else:
        starts = [m.start() - 0x80 for m in re.finditer(re.escape(BOARD_MARKER), data)]
    results = []
    for start in starts:
        if start < 0 or start + 0x94 > len(data):
            continue
        fields = [data[start + i:start + i + 32] for i in (0, 0x20, 0x40)]
        address = data[start + 0x89:start + 0x8f]
        if (data[start + 0x80:start + 0x88] != BOARD_MARKER
                or address in {b"\0" * 6, b"\xff" * 6}
                or not all(re.fullmatch(rb"[0-9a-fA-F]{32}", f) for f in fields)):
            continue
        results.append((start, address.hex(), fields[2].decode("ascii").lower()))
    return results


def show_keys(data, mac):
    records = find_keys(data, mac)
    if not records:
        print("No matching board data found in this range.")
        return 1
    for offset, address, key in records:
        print(f"Board offset: 0x{offset:x}; MAC: {address}; Desktop UploadKey: {key}")
    by_mac = {}
    for _, address, key in records:
        by_mac.setdefault(address, set()).add(key)
    if any(len(keys) > 1 for keys in by_mac.values()):
        print("Conflicting keys for the same MAC; no unique result.", file=sys.stderr)
        return 2
    return 0


def scan_dumps(channel, output, first, last, size, mac=None):
    """Save every requested range; do not mistake an unchanged response for a dump."""
    if output.drive.casefold() == channel.root.drive.casefold():
        raise ValueError("Output must be on a different drive from the card")
    output.mkdir(parents=True, exist_ok=False)
    summary = []
    all_records = []
    for index in range(first, last + 1):
        print(f"Reading dump {index}: {size} bytes...", flush=True)
        baseline = channel.transfer("RSPM")
        changed = False
        data = bytearray()
        target = output / f"dump{index}.response.bin"
        with target.open("xb") as stream:
            for offset in range(0, size, BLOCK):
                block = channel.request("k", index, offset)
                changed |= block != baseline
                stream.write(block)
                data.extend(block)
        records = find_keys(data, mac) if changed else []
        summary.append({
            "dump_index": index, "file": target.name,
            "requested_bytes": size, "response_changed": changed,
            "status": "board_data_found" if records else
                      "changed_response_no_board_data" if changed else
                      "unchanged_response_unconfirmed",
            "records": [{"offset": offset, "mac": address, "desktop_upload_key": key}
                        for offset, address, key in records],
        })
        # Retain partial scan results if a later slot cannot be read.
        (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        if not changed:
            print(f"Dump {index}: unchanged response; no dump confirmed.")
        elif records:
            show_keys(data, mac)
            all_records.extend(records)
        else:
            print(f"Dump {index}: response saved, no matching board data.")
    print(f"Scan saved in: {output}")
    print("Slots and range follow firmware 4.5166; no dump listing or EOF status is available.")
    if not all_records:
        return 1
    keys = {}
    for _, address, key in all_records:
        keys.setdefault(address, set()).add(key)
    if any(len(values) > 1 for values in keys.values()):
        print("Conflicting Desktop keys across dumps; see results.json.", file=sys.stderr)
        return 2
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = parser.add_subparsers(dest="action", required=True)
    extract = actions.add_parser("extract", help="Find keys in an existing local dump")
    extract.add_argument("file", type=Path)
    extract.add_argument("--mac", help="Optional MAC filter; default: detect board records")
    scan = actions.add_parser("scan", help="Read all three known firmware 4.5166 dump slots")
    scan.add_argument("drive", help="Card drive, for example H:")
    scan.add_argument("--output-dir", type=Path, help="New directory; default: timestamped folder beside script")
    scan.add_argument("--first-index", type=int, default=1)
    scan.add_argument("--last-index", type=int, default=3)
    scan.add_argument("--bytes", type=int, default=0x50000, help="Bytes per slot; default 327680 from firmware 4.5166")
    scan.add_argument("--mac", help="Optional MAC filter")
    for action in ("read", "log"):
        command = actions.add_parser(action, help="Read a dump range" if action == "read" else "Read a log range")
        command.add_argument("drive", help="Card drive, for example H:")
        command.add_argument("--output", required=True, type=Path, help="New file on another drive")
        command.add_argument("--offset", type=int, default=0)
        command.add_argument("--bytes", type=int, default=1048576 if action == "read" else BLOCK)
        if action == "read":
            command.add_argument("--dump-index", type=int, required=True, help="Existing dump number from card log")
            command.add_argument("--mac", help="Optional MAC filter")
    arguments = sys.argv[1:]
    if arguments and re.fullmatch(r"[a-zA-Z]:[\\/]?", arguments[0]):
        arguments = ["scan"] + arguments
    args = parser.parse_args(arguments)
    try:
        if args.action == "extract":
            return show_keys(args.file.read_bytes(), args.mac)
        if args.action == "scan":
            if not 0 <= args.first_index <= args.last_index <= 0xffffffff:
                parser.error("Invalid dump index range")
            if args.bytes <= 0 or args.bytes % BLOCK or args.bytes > 0x100000000:
                parser.error("Size must be a positive multiple of 16384, within 32-bit offsets")
            channel = WindowsChannel(args.drive)
            output = args.output_dir or Path(__file__).parent / ("eyefi-scan-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
            return scan_dumps(channel, output.resolve(), args.first_index,
                              args.last_index, args.bytes, args.mac)
        if args.bytes <= 0 or args.bytes % BLOCK or args.offset < 0 or args.offset % BLOCK:
            parser.error("Size and offset must be multiples of 16384; size must be positive")
        if args.offset + args.bytes > 0x100000000:
            parser.error("Requested range exceeds the 32-bit offset limit")
        channel = WindowsChannel(args.drive)
        output = args.output.resolve()
        if output.drive.casefold() == channel.root.drive.casefold():
            parser.error("Output must be on a different drive from the card")
        if output.exists():
            parser.error("Output already exists; choose a new filename")
        data = bytearray()
        # xb also protects against a file appearing between the check and open.
        with output.open("xb") as stream:
            for offset in range(args.offset, args.offset + args.bytes, BLOCK):
                block = channel.request("k" if args.action == "read" else "m",
                                        getattr(args, "dump_index", 0), offset)
                stream.write(block)
                data.extend(block)
                if len(data) % (16 * BLOCK) == 0:
                    print(f"Read {len(data)}/{args.bytes} bytes", flush=True)
        print(f"Saved {len(data)} bytes from offset {args.offset}: {output}")
        print("The protocol has no verified EOF/error status; an acknowledged request alone")
        print("does not prove that the dump exists or that the complete dump was read.")
        if args.action == "read":
            if args.offset:
                print("Board offsets below are relative to the saved range.")
            return show_keys(data, args.mac)
        return 0
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
