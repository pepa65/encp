# encp
**Simple data en/decryption**

## Usage
```
encp - Simple data en/decryption
Encrypt (default) or decrypt stdin or file to stdout with keyfile or password.
Usage:  encp [-d|--decrypt] [<file>] [<options>]
    Options:  [-q|--quiet] [-r|--random | -k|--keyfile] | -h|--help
        -r|--random:             Encrypt with random password (and display it)
        -k|--keyfile <keyfile>:  Use (part of) <keyfile> as the password
        -q|--quiet:              Suppress output on stderr (errors and prompts)
        -h|--help:               Show this help text (ignore all other options)
    A password must be entered if -r|--random and -k|--keyfile are not given.
```

### Examples of simple file encryption
```sh
encp secret.file >secret.file.encp
encp secret.file --random >secret.file.encp  # Will display the used password
```

### Examples of simple file decryption
```sh
encp --decrypt secret.file.encp --keyfile file.key >secret.file
encp -d secret.file.encp |less
```

### Example of encrypted file transfer
```sh
nc -l 6666 |encp --decrypt >destination.file
encp source.file |nc host.ip 6666
```

### Example of compressed encrypted archive
```sh
zstd --stdout "$file" |encp >"$file.zst.encp"
zstd --stdout "$file" |encp --keyfile file.key >"$file.zst.encp"
```

## Installation

Download the [precompiled single binary for amd64](https://gitlab.com/pepa65/encp/-/jobs/artifacts/master/raw/encp?job=building)
and make it executable with `chmod +x encp`.

Or clone the repository by `git clone https://gitlab.com/pepa65/encp`, do `cd encp` and do:

```sh
make
sudo make install
```

## Dependencies
None, [libhydrogen](https://libhydrogen.org) is included as a submodule.
It is updated by: `git pull -v --recurse-submodules`
