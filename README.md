# encp
**Simple data en/decryption**

## Usage
```
encp - Simple data en/decryption
Encrypting (default) or decrypting data with a keyfile or password.
Usage:
  encp [-d|--decrypt] [<in>] [-o|--output <out>] [<keyoptions>]
    <in>,<out>:    Files, or a literal '-' (read from stdin / write to stdout)
    <keyoptions>:
        -r|--random:    Encrypt with and display a randomly generated password
        -k|--keyfile <keyfile>:    Use <keyfile> as the password
  When no <keyoptions> are given, a password is asked for on stdin, in which
  case <in> needs to be a file.
```

### Example of simple file encryption
`encp secret.file --output secret.file.encp`

### Example of simple file decryption
`encp --decrypt secret.file.encp`

### Example of encrypted file transfer
```sh
nc -l 6666 |encp --decrypt --keyfile password.key  # Destination
encp --keyfile password.key secret.file |nc 127.0.0.1 6666  # Source
```

### Example of compressed encrypted archive
```sh
zstd --stdout "$file" |encp --output "$file.zst.encp"
```

## Dependencies
None, [libhydrogen](https://libhydrogen.org) is included as a submodule.

## Installation
```sh
make
sudo make install
```
