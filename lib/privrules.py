import sys
import yara
import os
import io

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

RSA_MOD_SIZE = 0x80
RSA_KEY_SIZE = 0x400

def read_rules_from_dir(directory):
    rulefiles = []
    dummy = ""
    for (dirpath, dirnames, filenames) in os.walk(directory):
        for filename in filenames:
            # print filename
            if filename[-4:] == ".yar":
                # file is a .yar file, add to rulefiles
                rulefiles.append(os.path.join(dirpath, filename))
    
    # testcompile rulefiles in order to find broken rules
    for rulefile in rulefiles:
        try:
            yara.compile(rulefile, externals={
                'filename': dummy,
                'filepath': dummy,
                'extension': dummy,
                'filetype': dummy,
                'md5': dummy,
            })
        except Exception, e:
            print "Error compiling rule %s (%s)" % (rulefile, e)
            sys.exit(-1)

    ruleset = ""
    for rulefile in rulefiles:
        with open(rulefile, "r") as f:
            ruleset += f.read()

    try:
        compiled_rules = yara.compile(source=ruleset, externals={
            'filename': dummy,
            'filepath': dummy,
            'extension': dummy,
            'filetype': dummy,
            'md5': dummy,
        })
    except Exception, e:
        print "Error compiling composed ruleset (%s)" % e
        sys.exit(-1)

    return compiled_rules


def generate_RSA_key(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    return key

def get_cipher_RSA_PKCS1_OAEP(rsakey):
    return PKCS1_OAEP.new(rsakey)

def generate_AES_key(keysize):
    return Random.new().read(keysize)

def get_cipher_AES(aeskey, iv):
    return AES.new(aeskey, AES.MODE_CFB, iv)

def encrypt(data, cipher):
    return cipher.encrypt(data)

def decrypt(data, cipher):
    return cipher.decrypt(data)

def export_RSA_key(key, file):
    derkey = key.exportKey("DER")
    with open(file, "wb") as f:
        n = f.write(derkey)
    return n

def import_RSA_key(file):
    with open(file, "rb") as f:
        return RSA.importKey(f.read())

def decrypt_rules(file_package):
    privkey = import_RSA_key("%s.key" % file_package)
    rsa_cipher = get_cipher_RSA_PKCS1_OAEP(privkey)
    with open(file_package, "rb") as f:
        encrypted_data = f.read()

    aeskey = decrypt(encrypted_data[:RSA_MOD_SIZE], rsa_cipher)
    aes_iv = encrypted_data[RSA_MOD_SIZE:RSA_MOD_SIZE + AES.block_size]

    aes_cipher = get_cipher_AES(aeskey, aes_iv)
    decrypted_rules = decrypt(encrypted_data[RSA_MOD_SIZE + AES.block_size:], aes_cipher)

    buffer = io.BytesIO(decrypted_rules)
    rules = yara.load(file=buffer)
    return rules