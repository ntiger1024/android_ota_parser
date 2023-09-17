#!/usr/bin/env python3

import update_metadate_pb2
import sys
import struct


def parse(ofile):
    offset = ofile.tell()
    magic = ofile.read(4)
    if magic != b"CrAU":
        print("Not OTA file.")
        return
    print("{:08x} Magic: CrAU".format(offset))
    offset += 4

    version, msize = struct.unpack(">QQ", ofile.read(16))
    print("{:08x} Version: {}".format(offset, version))
    print("{:08x} Manifest Size: 0x{:x}({})".format(offset + 8, msize, msize))
    offset += 16

    if version < 2:
        print("Not supported version: {}".format(version))
        return

    ssize, = struct.unpack(">I", ofile.read(4))
    print("{:08x} Manifest Signature Size: 0x{:x}({})".format(offset, ssize, ssize))
    offset += 4

    manifest = update_metadate_pb2.DeltaArchiveManifest()
    manifest.ParseFromString(ofile.read(msize))
    print("{:08x} Manifest".format(offset))
    # sig_offset = offset + msize + ssize + manifest.signatures_offset
    # print("    Payload Signature Offset: {}".format(sig_offset))
    # print("    Payload Signature Size: {}".format(manifest.signatures_size))
    offset += msize

    print("{:08x} Metadata Signature".format(offset))
    offset += ssize

    print("{:08x} Blob".format(offset))

    ofile.seek(-manifest.signatures_size, 2)
    offset = ofile.tell()
    print("{:08x} Payload Signature".format(offset))


def main():
    if len(sys.argv) != 2:
        print("Usage: {} file".format(sys.argv[0]))
        sys.exit(1)
    try:
        ofile = open(sys.argv[1], "rb")
        parse(ofile)
    except OSError as err:
        print("Error {}".format(err))
        sys.exit(1)


if __name__ == "__main__":
    main()