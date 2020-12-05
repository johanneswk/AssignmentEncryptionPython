#!/usr/bin/env python
# This program can hash a file, sign a file, store an encrypted session key
# and encrypt a file using a public and private key

__author__ = '{Johannes Kistemaker}'
__email__ = '{johannes.kistemaker@hva.nl}'

import os, sys, getopt, hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, asymmetric, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def args():
    # List possible arguments
    short_options = "k:fpk:f:o:"
    long_options = ["key_location=", "foreign_public_key_location=", "file_location=", "output_location="]

    # Values
    key = ""
    fp_key = ""
    file = ""
    output = ""

    # Get full command-line arguments
    full_cmd_arguments = sys.argv
    # Keep all but the first
    argument_list = full_cmd_arguments[1:]
    print(argument_list)

    try:
        arguments, values = getopt.getopt(argument_list, short_options, long_options)
    except getopt.error as err:
        # Output error, and return with an error code
        print(str(err))
        sys.exit(4)

    if not arguments:
        print("provide all necessary file locations as an argument!")
        print("usage: \n-k, --key_location")
        print("-fpk, --foreign_public_key_location")
        print("-f, --file_location")
        print("-o, --output\n")
        raise TypeError

    # Evaluate given options
    for current_argument, current_value in arguments:
        if current_argument in ("-k", "--key_location"):
            key = current_value
            print(key)
        elif current_argument in ("-fk", "foreign_public_key_location="):
            fp_key = current_value
            print(fp_key)
        elif current_argument in ("-f", "--file_location"):
            file = current_value
            print(file)
        elif current_argument in ("-o", "--output_location"):
            output = current_value
            print(output)
        else:
            print("provide all necessary file locations as an argument!")
            print("usage: \n-k, --key_location")
            print("-fpk, --foreign_public_key_location")
            print("-f, --file_location")
            print("-o, --output\n")
            raise TypeError

    return key, fp_key, file, output


def hasher():
    h = hashlib.sha256()
    with open("C:/Users/johan/Desktop/Software_Security/RSA_Pair_Gen.py", "rb") as file:
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
        with open(str(studentnumber) + ".hash", 'w') as f:
            f.write(str(file))
    elif arg == "signature":
        # Write signature to disk
        with open(str(studentnumber) + ".sign", 'w') as g:
            g.write(str(file))
    elif arg == "encrypted_file":
        # Write encrypted file to disk
        with open(str(studentnumber) + ".code", 'w') as h:
            h.write(str(file))
    elif arg == "iv":
        # Write iv to disk
        with open(str(studentnumber) + ".iv", 'w') as h:
            h.write(str(file))
    elif arg == "iv_foreign_pub":
        # Write iv encrypted with foreign public key to disk
        with open(str(studentnumber) + ".skeyc", 'w') as i:
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
        with open("C:/Users/johan/Desktop/Software_Security/frans.pem", "rb") as g:
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
        exit(3)


def encrypt_file():
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    with open("C:/Users/johan/Desktop/Software_Security/RSA_Pair_Gen.py", "rb") as file:
        file = file.read()
        padder = padding.PKCS7(256).padder()
        padded = padder.update(file)
        padded += padder.finalize()

    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded)
    encrypted += encryptor.finalize()

    # Encrypt iv with a public key
    frans_pub = read_public_key(arg="foreign")
    message = iv
    ciphertext = frans_pub.encrypt(message,
                                   asymmetric.padding.OAEP(
                                       mgf=asymmetric.padding.MGF1(
                                           algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(), label=None))
    # Write to disk both encrypted file and session key
    write_to_disk("encrypted_file", encrypted)
    write_to_disk("iv", iv)
    write_to_disk("iv_foreign_pub", ciphertext)

    return encrypted, iv, ciphertext


if __name__ == '__main__':
    try:
        # Parsing args
        key_location, fp_key_location, file_location, output_path = args()

        # Welcome and input
        print("Welcome to this generator\n")
        studentnumber = int(input("Enter your school student number: "))

        # Calculate hash from file
        hash_file, hash_file_hex = hasher()

        # Sign file
        signature_file = signing()
        # print(signature_file)

        # Test signature
        check_signature = test_signature()
        # if check_signature:
        #     print("Valid signature!")

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

    except:
        print("An error occurred!")
        exit(1)




