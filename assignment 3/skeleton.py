# /usr/bin/python

from base64 import b64encode, b64decode
from binascii import b2a_hex, a2b_hex

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


##################################################
# Loads the RSA key object from the location
# @param keyPath - the path of the key
# @return - the RSA key object with the loaded key
##################################################
def loadKey(keyPath, algorithm):
    # The RSA key
    key = None
    # Open the key file
    with open(keyPath, 'r') as keyFile:
        # Read the key file
        keyFileContent = keyFile.read()
        if algorithm == 'RSA':
            # Decode the key
            decodedKey = b64decode(keyFileContent)
            # Load the key
            key = RSA.importKey(decodedKey)
        if algorithm == 'AES':
            key = keyFileContent
    # Return the key
    return key


##################################################
# Signs the string using an RSA private key
# @param sigKey - the signature key
# @param string - the string
##################################################
def digSig(sigKey, string, algorithm):
    if algorithm == 'RSA':
        # Use RSA algorithm
        cipher = PKCS1_v1_5.new(sigKey)
        # base64 encode the ascii string
        return cipher.sign(string)
    if algorithm == 'AES':
        # Use AES algorithm, IV also use Key, MODE=CBC
        cipher = AES.new(sigKey, AES.MODE_CBC, sigKey)
        # base64 encode the ascii string
        return b2a_hex(cipher.encrypt(string.hexdigest()))


##########################################################
# Returns the file signature
# @param fileName - the name of the file
# @param privKey - the private key to sign the file with
# @return fileSig - the file signature
##########################################################
def getFileSig(fileName, privKey, algorithm):
    # 1. Open the file
    # 2. Read the contents
    # 3. Compute the SHA-512 hash of the contents
    # 4. Sign the hash computed in using the digSig() function you implemented.
    # 5. Return the signed hash; this is your digital signature
    with open(fileName) as f:
        content = f.read()
    # Compute the SHA-512 hash of the contents
    content_hash = SHA512.new(content)
    # Sign the computed hash
    signed_hash = digSig(privKey, content_hash, algorithm)
    return signed_hash,


###########################################################
# Verifies the signature of the file
# @param fileName - the name of the file
# @param pubKey - the public key to use for verification
# @param signature - the signature of the file to verify
##########################################################
def verifyFileSig(fileName, pubKey, signature, algorithm):
    # 1. Read the contents of the input file (fileName)
    # 2. Compute the SHA-512 hash of the contents
    # 3. Use the verifySig function you implemented in
    # order to verify the file signature
    # 4. Return the result of the verification i.e.,
    # True if matches and False if it does not match
    with open(fileName) as f:
        content = f.read()
    # Compute the SHA-512 hash of the contents
    content_hash = SHA512.new(content)
    # load public key if algorithm is RSA
    # load aes key if algorithm is AES
    pubKey = loadKey(pubKey, algorithm)
    # load signature computed before
    signature = loadSig(signature)
    signature = signature[0]
    return verifySig(content_hash, signature, pubKey, algorithm)


############################################
# Saves the digital signature to a file
# @param fileName - the name of the file
# @param signature - the signature to save
############################################
def saveSig(fileName, signature):
    # Signature is a tuple with a single value.
    # Get the first value of the tuple, convert it
    # to a string, and save it to the file (i.e., indicated
    # by fileName)
    # Get first value of the tuple
    signature = signature[0]
    # Convert it to a string
    signature = b64encode(signature)
    with open(fileName, 'wb+') as f:
        f.write(signature)


###########################################
# Loads the signature and converts it into a tuple
# @param fileName - the file containing the signature
# @return - the signature
###########################################
def loadSig(fileName):
    # Open the file, read the signature string, convert it
    # into an integer, and then put the integer into a single
    # element tuple
    # The RSA key
    with open(fileName, 'r') as SigFile:
        # Read the sig file
        SigFileContent = SigFile.read()
        # Decode the key
        sig = b64decode(SigFileContent)
    # Return the sig
    return sig,


#################################################
# Verifies the signature
# @param theHash - the hash
# @param sig - the signature to check against
# @param veriKey - the verification key
# @return - True if the signature matched and false otherwise
#################################################
def verifySig(theHash, sig, veriKey, algorithm):
    # signature using the verify() function of the
    # key and return the result
    if algorithm == 'RSA':
        # Use RSA algorithm
        cipher = PKCS1_v1_5.new(veriKey)
        return cipher.verify(theHash, sig)
    elif algorithm == 'AES':
        # Use AES algorithm, IV also use Key, MODE=CBC
        cipher = AES.new(veriKey, AES.MODE_CBC, veriKey)
        return theHash.hexdigest() == cipher.decrypt(a2b_hex(sig))
