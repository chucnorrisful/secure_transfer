# Secure Transfer
Encodes a file with AES and encrypts the used key with RSA to enable secure file transfer using asymmetric encoding.

## Usage
```bash
# build the tool (requires Go)
cd tool
go build

# generate a new RSA keypair
./tool.exe -g

# encode a file with a foreign public-key
./tool.exe -pub-key pathTo/foreignKey.pub fileToEncode

# decode a file that was encoded using your current publickey
./tool.exe -d theEncodedFile.zip
```
