#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Hash import HMAC
from Crypto.Util.Padding import pad, unpad
import struct

# To color things
from termcolor import colored
import logging

# command line argument
import argparse
import getpass


# This is the Logger we use to log the info, will change it later
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

logger.addHandler(ch)


class EncrypterDecrypter:
    def __init__(self, passwd:str ):

        # Generate the key to be used in Cipher and macing 
        derived_key = KDF.PBKDF2(passwd, salt=b'69420', dkLen=32)

        self.cipher_key, self.mac_key = derived_key[:16], derived_key[16:]

        # generate the AES cipher with the key

    def encrypt(self, filename: str, output: str = 'data.bin'):
        try:
            logger.info(f'Opening file {(colored(filename, "green"))}')
            f = open(filename, 'br')
            out = open(output, 'bw+')

            logger.info('Creating Header')
 
            # Creating the header for encryption
            header = filename.encode('utf-8')
            header = pad(header, block_size=16, style='pkcs7')
            ln_filename = struct.pack('I', len(header))

            header = ln_filename+header

            logger.info( f'Header {colored(header, "yellow")}' )

            # current_cipher = b''
            # current_block  = b'\x00'*16

            # Creating the header
            current_text   = pad(header + f.read(), AES.block_size)

            # Encrypting data
            cipher = AES.new(self.cipher_key, AES.MODE_CBC, IV=b'69'*8)
            logger.info(f"Encrypting data...")
            enc            = cipher.encrypt(current_text)

            # generating MAC
            self.mac = HMAC.new(self.mac_key)
            logger.info("Signing MAC")
            mac = self.mac.update(enc).digest()

            logger.info(f"MAC {colored(mac, 'yellow')}\t"+
                f"len={colored(len(mac), 'green')}")

            # Writing output
            enc += mac
            logger.info("Done")
            logger.info(f"Writting to {output}")
            ln = out.write(enc)
            logger.info(f"Wrote {colored(ln, 'green')} bytes")

            # while True:
            #     if len(current_text) == 0:
            #         break
            #     elif len(current_text) < 16:
            #         current_text = pad(current_text, AES.block_size)
            #     print(f"{current_text}, {current_block}, {current_cipher}")
            #     current_block = self.cipher.encrypt(xor_bytes(current_text, current_block))
            #     current_cipher += current_block
            #     current_text = f.read(16)

        except Exception as ex:
            print( ex )


    def decrypt(self, filename: str):
        try:
            logger.info("Started Decrypting")
            f = open(filename, 'rb')
            enc = f.read()
            mac = enc[-16:]
            cip = enc[:-16]

            logger.info("Verifying MAC")
            hmac = HMAC.new(self.mac_key)
            hmac.update(cip)

            # Update this insecure shit
            assert hmac.digest() == mac
            logger.info("Verified MAC")

            # decrypt actual data
            logger.info("Decrypting your data")
            decr = AES.new(self.cipher_key, AES.MODE_CBC, IV=b'69'*8)
            raw_data = unpad(decr.decrypt(cip), AES.block_size)
            logger.info("Decryption Done")

            # header parsing
            ln, raw_data = raw_data[:4], raw_data[4:]
            header_len = struct.unpack('I', ln)[0] 
            logger.info(f"Header length {header_len}")

            # file name parsing
            filename, data = unpad(raw_data[:header_len], 16), raw_data[header_len:]

            # writting to the filename
            f = open(filename.decode('utf-8'), 'wb+')
            f.write(data)

            # DONE
            logger.info("Done")

        except Exception as ex:
            print(ex)

def xor_bytes(m1, m2):
    return bytes([a^b for a,b in zip(m1, m2)])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    enc_dec_grp = parser.add_mutually_exclusive_group()
    enc_dec_grp.add_argument('-e', '--encrypt', help="use this flag to encrypt file",
        type=str)
    enc_dec_grp.add_argument('-d', '--decrypt',  help="use this to decrypt the file",
        type=str)

    parser.add_argument('-o', '--output', help="name of the output file",
        type=str, default='data.bin')

    args = parser.parse_args()

    passwd = getpass.getpass()
    encdec = EncrypterDecrypter(passwd)
    if args.encrypt:
        encdec.encrypt(args.encrypt, args.output)
    elif args.decrypt:
        encdec.decrypt(args.decrypt)


