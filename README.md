# AES (Advanced Encryption Standard) Symmetric Block Cipher

AES is a symmetric block cipher. It is symmetric because it uses the same key to encrypt and decrypt, and is a block cipher because it operates on individual, independent blocks of data. It is typically used for encryption and decryption.

## Usage

### Encryption

Full, end-to-end encryption of plaintext to ciphertext.

```sh
$ cat aes-key
-my-16-byte-key-
$ echo 'Hello, world!' | tiber --output-hex --key aes-key encrypt
b1a4cd8fc4d3544b5c51623be45f1fc9
```

### Decryption

Full, end-to-end decryption of ciphertext to plaintext.

```sh
$ echo 'b1a4cd8fc4d3544b5c51623be45f1fc9' | tiber --input-hex --key aes-key decrypt
Hello, world!
```

### Individual Steps

Apply a particular step of the AES algorithm: one of `sub-bytes`, `shift-rows`, `mix-columns`, or `add-round-key`.

```sh
$ echo 'Hello, world!' | ./target/release/tiber --key aes-key encrypt shift-rows
H,l or lo lw!e d
```
