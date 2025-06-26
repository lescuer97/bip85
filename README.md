# Go-BIP85

[![Go Reference](https://pkg.go.dev/badge/github.com/leowolf/bip85.svg)](https://pkg.go.dev/github.com/lescuer97/bip85)

This is a Go library for deriving BIP-39 mnemonic seeds from a BIP-32 master root key, based on the [BIP-85 specification](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki).

> **Note:** This library is an open-source project and is seeking community contributions and review to ensure it is production-ready. Your help in validating and improving the code is welcome!

## Features

- Derivation of BIP-39 mnemonics (12, 18, and 24 words).
- Initialization from a master mnemonic phrase (English only).
- Initialization from a master extended private key (XPRV).

## Usage

Here is a basic example of how to use the library:

```go
package main

import (
	"fmt"
	"log"

	"github.com/lescuer97/bip85"
)

func main() {
	// Initialize from a mnemonic
	mnemonic := "all all all all all all all all all all all all"
	passphrase := ""
	b, err := bip85.NewBip85FromMnemonic(mnemonic, passphrase)
	if err != nil {
		log.Fatal(err)
	}

	// Derive a new 12-word mnemonic
	derivedMnemonic, err := b.DeriveMnemonic(12, 0)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(derivedMnemonic)
}
```
