# /usr/bin/python

# Usage:
# python signer.py <KEY FILE NAME> <SIGNATURE FILE NAME> <INPUT FILE NAME> <MODE> [ALGORITHM]
# test rsa encrypt and decrypt
# python signer.py privKey.pem test_rsa.sig test.txt sign
# python signer.py pubKey.pem test_rsa.sig test.txt verify
# test aes encrypt and decrypt
# python signer.py aesKey.pem test_aes.sig test.txt sign AES
# python signer.py aesKey.pem test_aes.sig test.txt verify AES


import sys

from skeleton import loadKey, getFileSig, saveSig, verifyFileSig


# The main function
def main():
    # Make sure that all the arguments have been provided
    if len(sys.argv) < 5:
        print('USAGE: ' + sys.argv[0] + ' <KEY FILE NAME> <SIGNATURE FILE NAME> <INPUT FILE NAME>')
        exit(-1)
    # The key file
    keyFileName = sys.argv[1]
    # Signature file name
    sigFileName = sys.argv[2]
    # The input file name
    inputFileName = sys.argv[3]
    # The mode i.e., sign or verify
    mode = sys.argv[4]
    # The algorithm used
    if len(sys.argv) >= 6:
        algorithm = sys.argv[5]
    else:
        algorithm = 'RSA'
    # Load the key
    key = loadKey(keyFileName, algorithm)
    # We are signing
    if mode == 'sign':
        # 1. Get the file signature
        # 2. Save the signature to the file
        sig = getFileSig(inputFileName, key, algorithm)
        saveSig(sigFileName, sig)
        print('Signature saved to file {}'.format(sigFileName))
    # We are verifying the signature
    elif mode == 'verify':
        # Use the verifyFileSig() function to check if the
        # signature signature in the signature file matches the
        # signature of the input file
        if verifyFileSig(inputFileName, keyFileName, sigFileName, algorithm):
            print('Signatures match!')
        else:
            print('Signatures DO NOT MATCH!')
    else:
        print('Invalid mode', mode)


# Call the main function
if __name__ == '__main__':
    main()
