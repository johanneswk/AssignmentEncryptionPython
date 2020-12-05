#!/usr/bin/env python
# This program can hash a file, sign a file, store an encrypted session key
# and encrypt a file using a public and private key

__author__ = '{Johannes Kistemaker}'
__email__ = '{johannes.kistemaker@hva.nl}'

import os, sys, hashlib, argparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, asymmetric, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def terminal_args():
    # Initiate the parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', metavar="key_location" ,type=str, required=True, help="path to folder with RSA keys")
    parser.add_argument("-fpk", metavar="foreign_public_key_location", type=str, required=True, help="public key of receiver")
    parser.add_argument("-f", metavar="file_location", type=str, required=True, help="location of file to be encrypted")
    parser.add_argument("-o", metavar="output", type=str, required=True, help="path where files will be stored")

    # Read arguments from the command line
    args = parser.parse_args()

    # Check each location and print it
    # if not args.key_location:
        # sys.exit()
    # if args.foreign_public_key_location:
    #     print(args.foreign_public_key_location)
    # elif args.file_location:
    #     print(args.file_location)
    # elif args.output:
    #     print(args.output)

    return args.k, args.fpk, args.f, args.o


def hasher():
    h = hashlib.sha256()
    with open(file_location, "rb") as file:
        # loop till the end of the file
        chunk = 0
        while chunk != b'':
            # read only 1024 bytes at a time
            chunk = file.read(1024)
            h.update(chunk)

    # Write hash to disk
    write_to_disk("hash", h.hexdigest())

    # return the representation of digest
    return h.digest(), h.hexdigest()


def write_to_disk(arg, file):
    if arg == "hash":
        # Write hash to disk
        with open(str(output_location) + "/" + str(studentnumber) + ".hash", 'w') as f:
            f.write(str(file))
    elif arg == "signature":
        # Write signature to disk
        with open(str(output_location) + "/" + str(studentnumber) + ".sign", 'w') as g:
            g.write(str(file))
    elif arg == "encrypted_file":
        # Write encrypted file to disk
        with open(str(output_location) + "/" + str(studentnumber) + ".code", 'w') as h:
            h.write(str(file))
    # elif arg == "key":
    #     # Write key to disk
    #     with open(str(output_location) + "/" + str(studentnumber) + ".skey", 'w') as h:
    #         h.write(str(file))
    elif arg == "iv":
        # Write iv to disk
        with open(str(output_location) + "/" + str(studentnumber) + ".iv", 'w') as h:
            h.write(str(file))
    elif arg == "encrypted_skey":
        # Write iv encrypted with foreign public key to disk
        with open(str(output_location) + "/" + str(studentnumber) + ".skeyc", 'w') as i:
            i.write(str(file))


def read_private_key():
    with open(str(key_location) + "/" + str(studentnumber) + ".key", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())
        return private_key


def read_public_key(arg):
    if arg == "own":
        with open(str(key_location) + "/" + str(studentnumber) + ".pem", "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend())
            return public_key
    elif arg == "foreign":
        with open(foreign_public_key_location, "rb") as g:
            public_key = serialization.load_pem_public_key(
                g.read(), backend=default_backend())
            return public_key


def signing():
    # Open private key
    private_key = read_private_key()

    # Sign file with private key
    signature = private_key.sign(
        data=hash_file_hex.encode('utf-8'),
        padding=asymmetric.padding.PSS(
            mgf=asymmetric.padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric.padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )

    # Convert to hex
    hex_sig = signature.hex()
    write_to_disk("signature", hex_sig)

    return signature


def test_signature():
    try:
        read_public_key(arg="own").verify(
            signature=signature_file,
            data=hash_file_hex.encode('utf-8'),
            padding=asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        return True
    except InvalidSignature:
        print("Invalid signature")
        exit(4)


def encrypt_file():
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    with open(file_location, "rb") as file:
        file = file.read()
        padder = padding.PKCS7(256).padder()
        padded = padder.update(file)
        padded += padder.finalize()

    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded)
    encrypted += encryptor.finalize()
    data = encrypted + iv

    # Encrypt iv with a public key
    frans_pub = read_public_key(arg="foreign")
    message = key
    ciphertext = frans_pub.encrypt(message,
                                   asymmetric.padding.OAEP(
                                       mgf=asymmetric.padding.MGF1(
                                           algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(), label=None))
    # Write to disk both encrypted file and session key
    write_to_disk("encrypted_file", data)
    # write_to_disk("key", key)
    write_to_disk("iv", iv)
    write_to_disk("encrypted_skey", ciphertext)

    return data, iv, ciphertext


if __name__ == '__main__':
    try:
        # Parsing args
        key_location, foreign_public_key_location, file_location, output_location = terminal_args()

        # Welcome and input
        print("Welcome to this generator\n")
        studentnumber = int(input("Enter your school student number: "))

        # Calculate hash from file
        hash_file, hash_file_hex = hasher()

        # Sign file
        signature_file = signing()

        # Test signature
        check_signature = test_signature()

        # Encrypt file + iv with frans pub
        encrypted_file, session_key, crypto_session_key = encrypt_file()

        print("Succes!")

    except ValueError:
        # Catching user-input that cannot be parsed as an int
        print("Entered studentnumber is not correct!")
        exit(2)

    except TypeError:
        # User input error
        print("Supplied arguments are not valid!")
        exit(3)






