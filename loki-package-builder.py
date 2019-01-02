import sys
import argparse
import io

from lib.privrules import *

def parse_arguments():
    parser = argparse.ArgumentParser(description='Package builder for Loki')
    parser.add_argument('--ruledir', help='directory containing the rules to build into Loki', required=True)
    parser.add_argument('--target', help='target where to store the compiled ruleset', required=True)
    return parser.parse_args()

def main():
    args = parse_arguments()

    rules = read_rules_from_dir(args.ruledir)
    
    # stop if no private rules were found
    if rules == None:
        return

    buffer = io.BytesIO()
    rules.save(file=buffer)
    serialized_rules = buffer.getvalue()
    serialized_rules_compressed = compress(serialized_rules)
    rsakey = generate_RSA_key(RSA_KEY_SIZE)
    rsa_cipher = get_cipher_RSA_PKCS1_OAEP(rsakey.publickey())
    aes_iv = Random.new().read(AES.block_size)
    aeskey = generate_AES_key(32)
    aes_cipher = get_cipher_AES(aeskey, aes_iv)
    encrypted_rules = encrypt(serialized_rules_compressed, aes_cipher)
    encrypted_rules = aes_iv + encrypted_rules
    encrypted_aes_key = encrypt(aeskey, rsa_cipher)
    encrypted_rules = encrypted_aes_key + encrypted_rules

    with open(args.target, "wb") as f:
        f.write(str(encrypted_rules))

    n = export_RSA_key(rsakey, "%s.key" % args.target)

    if decrypt_rules(args.target) == None:
        print "unable to decrypt package"
        sys.exit(-1)


if __name__ == "__main__":
    main()