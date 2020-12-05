# Encryption, hashing and signing in Python

This script was made so that a file can be sent securely. 
It does this by:

- Creating a hash of the specified file;

- Signing the hash;

- Encrypting the file using AES;

- Encrypting the session-key with a (foreign) public key.




**Parameters:**
This script needs 4 arguments supplied from the terminal to function.
1. `-k` path to folder with RSA keys
2. `-f` location of file to be encrypted
3. `-fpk` public key of the receiver
4. `-o` path where files will be stored



**Usage example:** 
`python3 CryptoOperations.py -k ~\RsaPair -f ~/RSA_Pair_Gen.py -fpk ~/Downloads/frans.pem -o ~/Documents/EncryptionAssignment`

**Usage example 2:** 
`python3 CryptoOperations.py -k C:\Users\johan\PycharmProjects\RsaPair -f C:\Users\johan\Desktop\Software_Security\RSA_Pair_Gen.py -fpk C:\Users\johan\Desktop\Software_Security\frans.pem -o C:\Users\johan\PycharmProjects\AssignmentEncryptionPython`
