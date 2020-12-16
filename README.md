# imgcrypt

`imgcrypt` is a CLI utility to AES encrypt RGB images. Idea taken from [this online tool](https://encrypt.imageonline.co/).
I simply wanted a command-line version that doesn't leak the same metadata.

## Crypto Details

Uses AES in CTR mode with random IV and 256-bit key. Key derivation happens via PBKDF2 with a random salt.

## How it Works

The image is read into a 3D array (RGB) and flattened to 1D before being passed through the encryption function.
The salt and IV are stored in the `User Comment` EXIF tag and read out/utilized on decrypt.

## Examples

**Encrypted**

![](examples/encrypted.png) 

**Decrypted**

![](examples/decrypted.png)

## Usage

```
usage: imgcrypt.py [-h] [-e ENCRYPT] [-d DECRYPT] [-p PASSWORD] [-o OUTPUT_FILE]

AES encrypt image

optional arguments:
  -h, --help            show this help message and exit
  -e ENCRYPT, --encrypt ENCRYPT
                        encrypt image
  -d DECRYPT, --decrypt DECRYPT
                        decrypt image
  -p PASSWORD, --password PASSWORD
                        password for encryption/decryption
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output file
```

## License

None, send some private images to friends.