# Simple Asymmetric File encryption

This simple python application:
- Generates RSA private and public key pairs
- Creates a sha256 hash of a test file
- Encrypts the file hash using private key 
- Stores the encrypted hash as binary encrypted test file
- Then decrypts the encrypted test file to generate the original file hash

## Setup

Start python virtual env with venv for installing required pip modules
```
python3 -m venv env
source env/bin/activate
```

OR run setup script to start venv, download required pip module and run the py file
```
./setup.sh
```

