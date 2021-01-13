# encp
**Simple data en/decryption**

## Usage
```
encp - Simple data en/decryption
Encrypting (default) or decrypting data with a keyfile or password.
Usage:
  encp [-d|--decrypt] [<in> | -o|--output <out>] [<options>] [<keyoptions>]
    <in>,<out>:                  Files / '-' (read from stdin, write to stdout)
    <options>:
        -f|--force:              Encrypted data to stdout (to file otherwise)
        -q|--quiet:              Surpress output on stderr (errors and prompts)
        -h|--help:               Show this help text
    <keyoptions>:
        -r|--random:             Encrypt with a random password and display it
        -k|--keyfile <keyfile>:  Use (part of) <keyfile> as the password
  When no <keyoptions> are given, a password is asked for on stdin, in which
  case <in> needs to be a file.
  When encrypting, and <out> is not a file, and the output is not being piped,
  and the -f|--forced flag is not given, the output goes to a file named
  'file-XXXXXXXX.encp' (XXXXXXXX is a random 4-byte hexadecimal).
```

### Examples of simple file encryption
```sh
encp secret.file --output secret.file.encp
encp secret.file
```

### Examples of simple file decryption
```sh
encp --decrypt secret.file.encp
encp -d secret.file.encp |less

### Example of encrypted file transfer
```sh
nc -l 6666 |encp --decrypt --keyfile password.key  # Destination
encp --keyfile password.key secret.file |nc 127.0.0.1 6666  # Source
```

### Example of compressed encrypted archive
```sh
zstd --stdout "$file" |encp --output "$file.zst.encp"
```

## Installation
```sh
make
sudo make install
```

## Dependencies
None, [libhydrogen](https://libhydrogen.org) is included as a submodule.
