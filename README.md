# AES (Advanced Encryption Standard) Symmetric Block Cipher

![Coverage](doc/coverage.svg)

AES is a symmetric block cipher. It is symmetric because it uses the same key to encrypt and decrypt, and is a block cipher because it operates on individual, independent blocks of data. It is typically used for encryption and decryption.

## Usage

### Encryption

Full, end-to-end encryption of plaintext to ciphertext.

```sh
$ cat aes.key
-my-16-byte-key-
$ echo 'Hello, world!' | tiber --output-hex encrypt --key aes.key
b1a4cd8fc4d3544b5c51623be45f1fc9
```

### Decryption

Full, end-to-end decryption of ciphertext to plaintext.

```sh
$ echo 'b1a4cd8fc4d3544b5c51623be45f1fc9' | tiber --input-hex decrypt --key aes.key
Hello, world!
```

### Individual Steps

Apply a particular step of the AES algorithm: one of `sub-bytes`, `shift-rows`, `mix-columns`, or `add-round-key`.

```sh
$ echo 'Hello, world!' | tiber shift-rows
H,l or lo lw!e d
```

### CBC Mode

Pass `--cbc` and a 32-character hex initialisation vector to use Cipher Block Chaining mode.

```sh
$ echo 'Hello, world!' | tiber --output-hex encrypt --key aes.key --cbc --iv 000102030405060708090a0b0c0d0e0f
7f2c9a1e8b3d5f04a6c8e2109d7b4f31
$ echo '7f2c9a1e8b3d5f04a6c8e2109d7b4f31' | tiber --input-hex decrypt --key aes.key --cbc --iv 000102030405060708090a0b0c0d0e0f
Hello, world!
```

## Benchmarking

### tiber-bench

Measures AES-128-CBC encryption throughput across six standard block sizes, mirroring `openssl speed`.

```sh
$ cargo build --release --bin tiber-bench
$ ./target/release/tiber-bench
Doing AES-128-CBC ops for 3s on 16 size blocks: ...
...
type                 16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
AES-128-CBC         79357.15k    81382.50k    81584.27k    81831.01k    81720.39k    81889.64k
```

Use `--seconds N` to change the duration per block size (default: 3):

```sh
$ ./target/release/tiber-bench --seconds 1
```

### Comparison with OpenSSL (ARM only)

`bin/benchmark_compare.py` runs tiber-bench, `openssl speed`, and `openssl speed` with hardware AES extensions disabled (`OPENSSL_armcap=0x0`), then writes the results to a CSV.

```sh
$ cargo build --release --bin tiber-bench
$ python bin/benchmark_compare.py
$ python bin/benchmark_compare.py --seconds 1 --output results.csv
```

The output CSV contains throughput (KB/s) for each implementation and a speedup ratio row for each OpenSSL variant relative to Tiber:

```
implementation,16 bytes,64 bytes,256 bytes,1024 bytes,8192 bytes,16384 bytes
tiber,79962.62,81382.50,...
openssl-no-ext,298109.54,320872.58,...
openssl,616478.02,1418600.58,...
openssl-no-ext / tiber,3.7x,3.9x,...
openssl / tiber,7.7x,17.4x,...
```

## Web Interface

The cipher can be interacted with through a web interface, by running the following command and opening [localhost:8080](http://localhost:8080).

```sh
$ docker run -p 8080:80 benmandrew/tiber
```

![Tiber web interface](doc/screenshot.png)

## Build

```sh
$ make
```

## Documentation

Code docs are located online at [benmandrew.com/docs/tiber/tiber/](https://benmandrew.com/docs/tiber/tiber/), or can be generated locally with

```sh
$ cargo doc --no-deps --open
```

## Fuzzing

Fuzz test inputs to the cipher with

```sh
$ docker run benmandrew/tiber:fuzz
```

Each input is encrypted and decrypted to check idempotence, and the binary is built with ASan to detect memory errors.
