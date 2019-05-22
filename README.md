# ruby-bitcoin-secp256k1

## Prerequisite

In order to use this gem, [libsecp256k1](https://github.com/bitcoin/secp256k1) must be in place.

### macOS

```bash
brew tap nervosnetwork/tap
brew install libsecp256k1
```

### Ubuntu 18.04 or above

```bash
sudo apt install libsecp256k1-dev
```

### Ubuntu 16.04 or below

```
$ git clone https://github.com/bitcoin-core/secp256k1.git && cd secp256k1
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

Or if you have cloned the project, you could go to project root and run this install script:

```
git submodule update --init --recursive
./install_lib.sh
```

The recovery and ecdh modules are optional. If your local installation of secp256k1 doesn't enable them then the gem would throw `LoadModuleError` when related functions are invoked.

## Install

```
gem i bitcoin-secp256k1
```

Then `require 'secp256k1'` (without `bitcoin-` prefix) in your source code.

## Usage

Check [test](test) for examples.

## LICENSE

[MIT License](LICENSE)

