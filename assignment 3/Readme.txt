Partners:
Programming Language: Python 3
How to execute:
    python signer.py <KEY FILE NAME> <SIGNATURE FILE NAME> <INPUT FILE NAME> <MODE> [ALGORITHM]
    test rsa encrypt and decrypt
        python signer.py privKey.pem test_rsa.sig test.txt sign
        python signer.py pubKey.pem test_rsa.sig test.txt verify
    test aes encrypt and decrypt
        python signer.py aesKey.pem test_aes.sig test.txt sign AES
        python signer.py aesKey.pem test_aes.sig test.txt verify AES
Extra Credit: Finished


