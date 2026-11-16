#!/usr/bin/env python3
"""Copy the entry image to the output directory, unchanged, after validating it.

The image lives beside this file as entry.png. It may hold PNG or JPEG bytes
(the gate tells them apart by magic bytes); either way the output keeps the
name entry.png. The output directory is $MAKEFUN_OUTPUT_DIR when set, else
/output. Standard library only, no network, fully deterministic: the same
input bytes always produce the same output bytes.
"""

import os
import struct
import sys
import zlib

MAX_BYTES = 1048576
MAX_DIMENSION = 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"


def fail(message):
    print("error: " + message, file=sys.stderr)
    raise SystemExit(1)


def check_png(data):
    """Walk every chunk, verifying CRCs, through IEND; return (width, height)."""
    if len(data) < 8 + 25:
        fail("PNG file too short")
    width, height = struct.unpack(">II", data[16:24])
    if data[12:16] != b"IHDR":
        fail("PNG first chunk is not IHDR")
    pos = 8
    saw_iend = False
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if end > len(data):
            fail("PNG chunk overruns file")
        expected = struct.unpack(">I", data[end - 4:end])[0]
        actual = zlib.crc32(data[pos + 4:end - 4]) & 0xFFFFFFFF
        if actual != expected:
            fail("PNG chunk %r has a bad CRC" % chunk_type)
        if chunk_type == b"IEND":
            saw_iend = True
            if end != len(data):
                fail("PNG has trailing bytes after IEND")
            break
        pos = end
    if not saw_iend:
        fail("PNG file has no IEND chunk")
    return width, height


def check_jpeg(data):
    """Walk segments to SOS, read dimensions from SOF, scan to the EOI marker.

    After the start-of-scan segment the entropy-coded data is scanned for a
    real 0xFFD9 end marker, skipping byte-stuffed 0xFF00 pairs and restart
    markers; anything after EOI is rejected.
    """
    pos = 2
    dims = None
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            fail("JPEG segment marker expected")
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        size = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if size < 2 or pos + 2 + size > len(data):
            fail("JPEG segment overruns file")
        if marker in (0xC0, 0xC1, 0xC2):
            height, width = struct.unpack(">HH", data[pos + 5:pos + 9])
            dims = (width, height)
        if marker == 0xDA:
            scan = pos + 2 + size
            while scan + 1 < len(data):
                if data[scan] == 0xFF and data[scan + 1] != 0x00:
                    if data[scan + 1] == 0xD9:
                        if scan + 2 != len(data):
                            fail("JPEG has trailing bytes after EOI")
                        if dims is None:
                            fail("JPEG file has no start-of-frame marker")
                        return dims
                    if not 0xD0 <= data[scan + 1] <= 0xD7:
                        fail("JPEG scan data ends at an unexpected marker")
                scan += 1
            fail("JPEG file lacks its end marker")
        pos += 2 + size
    fail("JPEG file has no start-of-scan segment")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "entry.png"), "rb") as handle:
        data = handle.read()
    if len(data) > MAX_BYTES:
        fail("image is %d bytes, over the 1048576 limit" % len(data))
    if data[:8] == PNG_MAGIC:
        width, height = check_png(data)
    elif data[:3] == JPEG_MAGIC:
        width, height = check_jpeg(data)
    else:
        fail("image is neither PNG nor JPEG")
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        fail("image is %dx%d, over the 1024x1024 limit" % (width, height))
    out_dir = os.environ.get("MAKEFUN_OUTPUT_DIR") or "/output"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "entry.png")
    with open(out_path, "wb") as handle:
        handle.write(data)
    print("wrote %d bytes (%dx%d) to %s" % (len(data), width, height, out_path))


if __name__ == "__main__":
    main()
