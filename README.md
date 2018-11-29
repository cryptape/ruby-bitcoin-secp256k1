# ruby-bitcoin-secp256k1

## Prerequiste

In order to use this gem, [libsecp256k1](https://github.com/bitcoin/secp256k1) with recovery module enabled must be in place.

```
$ git clone https://github.com/bitcoin-core/secp256k1.git && cd secp256k1
$ ./autogen.sh
$ ./configure --enable-module-recovery
$ make
$ sudo make install
```

If you have cloned the project and in project root:

```
git submodule update --init --recursive
./install_lib.sh
```

## Install

```
gem i bitcoin-secp256k1
```

Then `require 'secp256k1'` (without `bitcoin-` prefix) in your source code.

## Usage

Check [test](test) for examples.

## LICENSE

[MIT License](LICENSE)

