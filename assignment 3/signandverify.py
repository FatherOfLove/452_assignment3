# /usr/bin/python

#################################################################################
# This file gives an example of generating a digital signature and verifying it
#################################################################################

from base64 import b64decode

from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA


##################################################
# Loads the RSA key object from the location
# @param keyPath - the path of the key
# @return - the RSA key object with the loaded key
##################################################
def loadKey(keyPath):
    # The RSA key
    key = None

    # Open the key file
    with open(keyPath, 'r') as keyFile:
        # Read the key file
        keyFileContent = keyFile.read()

        # Decode the key
        decodedKey = b64decode(keyFileContent)

        # Load the key
        key = RSA.importKey(decodedKey)

    # Return the key
    return key


# Load the public and private keys from files
pubKey = loadKey('pubKey.pem')
privKey = loadKey('privKey.pem')

# The data to be digitally signed
data = b'hello world'

############## GENERATING SIGNATURE #####################

# First, lets compute the SHA-512 hash of the data
dataHash = SHA512.new(data).hexdigest()

# Lets generate the signature by encrypting our hash with the private key
dataSig = privKey.sign(dataHash, '')

############# VERIFYING THE SIGNATURE ####################

# First, lets compute the SHA-512 hash of the data
dataHash = SHA512.new(data).hexdigest()

# Now, verify the signature against the hash. I.e., the verify function
# will decrypt the digital signature using the public key and then compare
# the decrypted result to the dataHash

if pubKey.verify(dataHash, dataSig) is True:
    print('Match!')
else:
    print('No match!')
