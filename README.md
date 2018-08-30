# Detsign

Use passphrases to generate deterministic ED25519 signing keys using the
excellent libsodium. It is possible to use a 64bit subkeyid to generate many
signing key pairs from one single passphrase. Keys are derived using ARGON2 and BLAKE2.

## Commandline Help

```
Usage: detsign COMMAND [ARGS]...

Options: 
  -p PUB        Path to public key, required file extension: .detsign.pub
  -s SEC        Path to secret key, required file extension: .detsign.sec
  -d SIG        Path to signature file, required file extension: .detsign.sig
  -i SUBKEYID   Specify the subkeyid (a 64 bit unsigned integer),
                hence many keypairs can be derived from the same passphrase,
                default is 0.

Commands:
  gen -p PUB [-s SEC] [-i SUBKEYID]
    Generate a signing keypair and save to disk.
    If argument SEC is not set, don't save the secret key.

  gen-sign [-d SIG] [-i SUBKEYID] FILE
    Generate the keypair on the fly using a passphrase and sign FILE.
    If argument SIG is not set, save to FILE.detsign.sig.

  sign -s SEC [-d SIG] [FILE]
    Sign FILE and save signature to SIG.
    If argument SIG is not set, save to FILE.detsign.sig.
    If argument FILE is not set, read data from stdin, in which case
    argument SIG has to be given.

  verify -p PUB [-d SIG] [FILE]
    Verify a signature.
    If argument SIG is not set, use FILE.detsign.sig
    If argument FILE is not set, read data from stdin, in which case
    argument SIG has to be given.

  regen-pub -s SEC -p PUB
    Recreate the pulickey PUB from secret key SEC
```

## Building

### Using pkg-config and cmake (libsodium has to be installed)
```sh
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

### Using conan

```sh
which conan || pip install --user conan && hash -r
conan remote add -f bincrafters "https://api.bintray.com/conan/bincrafters/public-conan"
mkdir -p build
cd build
conan install ..
conan build ..
```
