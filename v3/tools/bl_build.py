#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
from Crypto.Random import get_random_bytes
from pwn import *
from datetime import datetime

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

def arrayize(binary_string):
    return '{' + ','.join([hex(char) for char in binary_string]) + '}'


def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)
    
    aes_key = get_random_bytes(16)
    iv = bytes((str(datetime.utcnow().timestamp()*1000000)+'A'*64)[:64],'utf-8')
    aad = get_random_bytes(16)
    
    with open('secret_build_output.txt', 'wb+') as f:
        f.write(aes_key)
        f.write(iv)
        f.write(aad)
        
        
    with open('./src/secrets.h', 'w') as f:
        f.write("#ifndef SECRETS_H\n")
        f.write("#define SECRETS_H\n")
        f.write("const uint8_t AES_KEY[16] = " + arrayize(aes_key) + ";\n")
        f.write("const uint8_t IV[10] = " + arrayize(iv) + ";\n")
        f.write("const uint8_t AAD[10] = " + arrayize(aad) + ";\n")
        f.write("#endif")
        
    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )

    copy_initial_firmware(firmware_path)
    make_bootloader()
