#!/usr/bin/env python3

import argparse
import binascii
import os
from io import BytesIO
from sys import stderr

import numpy as np
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter
from PIL import Image
from PIL.ExifTags import TAGS
from PIL.TiffImagePlugin import ImageFileDirectory_v2

SALT_BYTES = 8
KEY_BYTES = 32
_TAGS_r = dict(((v, k) for k, v in TAGS.items()))


def encrypt(password, bytes):
    """
    Encrypt bytes using AES 256 in CTR mode

    :param password: password to derive key from using PBKDF2
    :param bytes: bytes to encrypt
    """
    rand = Random.new()
    salt = rand.read(SALT_BYTES)
    key = PBKDF2(password, salt, KEY_BYTES)
    iv = rand.read(AES.block_size)
    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return salt, iv, aes.encrypt(bytes)


def decrypt(password, iv, salt, bytes):
    """
    Decrypt bytes using AES 256 in CTR mode

    :param password: password to derive key from using PBKDF2
    :param iv: initialization vector
    :param salt: salt used with PBKDF2 for key derivation
    :param bytes: bytes to decrypt
    """
    key = PBKDF2(password, salt, KEY_BYTES)
    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(bytes)


def reshape_and_save(bytes, width, height, file_name, iv=None, salt=None):
    """
    Reshape bytes into numpy array and save with salt/IV in 'User Comment' EXIF
    :param bytes: bytes to reshape
    :param file_name: output file name
    :param iv: initialization vector
    :param salt: salt used with PBKDF2 for key derivation
    """
    from_bytes = np.frombuffer(bytes, dtype=np.uint8)
    reshaped = np.reshape(from_bytes, (height, width, 3))
    reshaped_img = Image.fromarray(reshaped)

    # If salt/iv are present, write EXIF data
    if salt is not None and iv is not None:
        ifd = ImageFileDirectory_v2()
        iv_hex = binascii.hexlify(iv).decode('utf-8')
        salt_hex = binascii.hexlify(salt).decode('utf-8')
        ifd[_TAGS_r["UserComment"]] = u"{}{}".format(iv_hex, salt_hex)
        out = BytesIO()
        ifd.save(out)
        exif_bytes = b"Exif\x00\x00" + out.getvalue()
        reshaped_img.save(file_name, exif=exif_bytes)
    else:
        reshaped_img.save(file_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AES encrypt image")
    parser.add_argument("-e", "--encrypt", help="encrypt image")
    parser.add_argument("-d", "--decrypt", help="decrypt image")
    parser.add_argument("-p", "--password", help="password for encryption/decryption")
    parser.add_argument("-o", "--output-file", help="output file")
    argparse_namespace = parser.parse_args()

    if not argparse_namespace.encrypt and not argparse_namespace.decrypt:
        parser.print_help(stderr)
        parser.exit()
    if argparse_namespace.encrypt and argparse_namespace.decrypt:
        parser.print_help(stderr)
        parser.exit("can't encrypt and decrypt simultaneously")
    if not argparse_namespace.password:
        parser.print_help(stderr)
        parser.exit("please provide password")
    if not argparse_namespace.output_file:
        parser.print_help(stderr)
        parser.exit("please provide output file")
    if argparse_namespace.encrypt:
        if not os.path.isfile(argparse_namespace.encrypt):
            parser.error("file does not exist")
        else:
            img = Image.open(argparse_namespace.encrypt)
            width, height = img.size
            img_data = np.asarray(img)
            img_data_flattened = img_data.flatten()
            salt, iv, encrypted = encrypt(argparse_namespace.password, img_data_flattened.tobytes())
            reshape_and_save(encrypted, width, height, argparse_namespace.output_file, iv, salt)
    if argparse_namespace.decrypt:
        if not os.path.isfile(argparse_namespace.decrypt):
            parser.error("file does not exist")
        else:
            img = Image.open(argparse_namespace.decrypt)
            width, height = img.size
            exif = img._getexif()
            iv_salt = binascii.unhexlify(exif[_TAGS_r["UserComment"]])
            iv = iv_salt[:AES.block_size]
            salt = iv_salt[AES.block_size:]
            img_data = np.asarray(img)
            img_data_flattened = img_data.flatten()
            decrypted = decrypt(argparse_namespace.password, iv, salt, img_data_flattened.tobytes())
            reshape_and_save(decrypted, width, height, argparse_namespace.output_file)
