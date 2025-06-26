
package bip85

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
    "errors"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// BIP85 wraps a BIP32 master key.
type BIP85 struct {
	masterKey *bip32.Key
}

// NewFromMnemonic creates a new BIP85 instance from a BIP39 mnemonic.
func NewFromMnemonic(mnemonic, passphrase string) (*BIP85, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return &BIP85{masterKey: masterKey}, nil
}

// FromXPRV allows direct import of an existing BIP-32 root key.
func FromXPRV(xprv string) (*BIP85, error) {
	masterKey, err := bip32.B58Deserialize(xprv)
	if err != nil {
		return nil, err
	}
	return &BIP85{masterKey: masterKey}, nil
}


// DeriveMnemonic derives a new BIP39 mnemonic using the BIP85 algorithm.
func (b *BIP85) DeriveMnemonic(wordCount int, index uint32) (string, error) {
    // Correctly derive child key as per BIP-85 specification
    path := []uint32{83696968, 39, 0, uint32(wordCount), index}
    key := b.masterKey
    for _, p := range path {
        var err error
        key, err = key.NewChildKey(p + 0x80000000) // Apply hardening
        if err != nil {
            return "", fmt.Errorf("failed to derive child key: %w", err)
        }
    }

    // Use the private key bytes (32 bytes) for HMAC
    privateKeyBytes := key.Key[1:]

    // Compute HMAC-SHA512
    mac := hmac.New(sha512.New, []byte("bip-entropy-from-k"))
    mac.Write(privateKeyBytes)
    hash := mac.Sum(nil)

    // Determine required entropy length
    var entropyLength int
    switch wordCount {
    case 12:
        entropyLength = 16
    case 18:
        entropyLength = 24
    case 24:
        entropyLength = 32
    default:
        return "", fmt.Errorf("unsupported word count: %d", wordCount)
    }

    // Truncate hash to get entropy
    entropy := hash[:entropyLength]

    // Generate mnemonic from entropy
    mnemonic, err := bip39.NewMnemonic(entropy)
    if err != nil {
        return "", fmt.Errorf("failed to generate mnemonic: %w", err)
    }

    return mnemonic, nil
}
