
package bip85

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// Bip85 wraps a BIP32 master key for BIP85 derivations.
type Bip85 struct {
	masterKey *bip32.Key
}

// NewBip85FromMnemonic creates a new Bip85 instance from a BIP39 mnemonic.
// This implementation only supports the English wordlist.
func NewBip85FromMnemonic(mnemonic, passphrase string) (*Bip85, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is not valid or not in English")
	}
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return &Bip85{masterKey: masterKey}, nil
}

// NewBip85FromXPRV allows direct import of an existing BIP-32 root key.
func NewBip85FromXPRV(xprv string) (*Bip85, error) {
	masterKey, err := bip32.B58Deserialize(xprv)
	if err != nil {
		return nil, err
	}
	return &Bip85{masterKey: masterKey}, nil
}

// DeriveMnemonic derives a new BIP39 mnemonic using the BIP85 algorithm.
func (b *Bip85) DeriveMnemonic(wordCount int, index uint32) (string, error) {
	path := []uint32{
		bip32.FirstHardenedChild + 83696968,
		bip32.FirstHardenedChild + 39,
		bip32.FirstHardenedChild + 0,
		bip32.FirstHardenedChild + uint32(wordCount),
		bip32.FirstHardenedChild + index,
	}

	key := b.masterKey
	for _, p := range path {
		var err error
		key, err = key.NewChildKey(p)
		if err != nil {
			return "", fmt.Errorf("failed to derive child key: %w", err)
		}
	}

	if !key.IsPrivate {
		return "", errors.New("derived key is not a private key")
	}

	privateKeyBytes := key.Key[1:]

	mac := hmac.New(sha512.New, []byte("bip-entropy-from-k"))
	mac.Write(privateKeyBytes)
	hash := mac.Sum(nil)

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

	entropy := hash[:entropyLength]

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return mnemonic, nil
}
