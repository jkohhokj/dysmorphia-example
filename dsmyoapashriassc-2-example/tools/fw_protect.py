#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from pwn import *


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        
        
    with open('../bootloader/secret_build_output.txt', 'rb') as secrets_file:
        shift_key = u8(secrets_file.read(1))

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'
    
    encrypted_firmware = b''
    encrypted_chunk = b''
    for c in range(len(firmware_and_message)):
        encrypted_chunk = p8((firmware_and_message[c]+shift_key)&0xFF)
        encrypted_firmware += encrypted_chunk



    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + encrypted_firmware

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
