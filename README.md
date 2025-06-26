> **CAUTION:** This library is a work in progress and has known issues, most notably that it does not currently reproduce the official BIP-85 test vectors. It should not be used for production applications without further validation and verification.

# Go-BIP85 Library

## Overview

This is a Go library for deriving BIP-39 mnemonic seeds from a BIP-32 master root key, based on the BIP-85 specification.

It allows you to use a single master key to generate multiple unique mnemonic seeds for different wallet applications, enhancing backup security and simplicity.

## Features

- Derivation of BIP-39 mnemonics (12, 18, and 24 words).
- Initialization from a master mnemonic phrase (English only).
- Initialization from a master extended private key (XPRV).

## Important Limitations

This implementation has several important limitations that users must be aware of:

1.  **Does Not Reproduce Official BIP-85 Test Vectors:** The library **does not** currently generate the same mnemonics as the official test vectors published in the BIP-85 specification. This is believed to be due to a subtle incompatibility or bug in the required `github.com/tyler-smith/go-bip32` library (v1.0.0), which causes a divergence in the key derivation process. The library is, however, internally consistent: it will always produce the same derived mnemonic from the same master key.

2.  **XPRV Derivation Not Supported:** The BIP-85 application for deriving a new XPRV (`m/83696968'/32'/{index}'`) is **not implemented**. This is due to a technical limitation in the `go-bip32` library dependency, which prevents the creation of a new root key from its constituent parts in the manner required by the specification.

3.  **English Wordlist Only:** The library exclusively supports the English wordlist for both input mnemonics and derived mnemonics.

4.  **BIP-39 Application Only:** This library only implements the BIP-39 derivation application (`m/83696968'/39'/...`). Other applications defined in BIP-85 (such as WIF, HEX, PWD, etc.) are not included.

## Usage

Here is a basic example of how to use the library:

```go
package main

import (
	"fmt"
	"log"

	"your_module/bip85"
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
	// Expected output (due to library limitation, this does not match the official spec):
	// dragon great exhaust dice owner element tank canal cliff brand vibrant twelve
}
```
