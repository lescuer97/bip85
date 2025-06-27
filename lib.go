package bip85

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var (
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")
)

type DerivationType uint

const Mnemonic DerivationType = 39
const Xprv DerivationType = 32

type MnemonicLanguage uint

const English MnemonicLanguage = 0

// Bip85 wraps a BIP32 master key for BIP85 derivations.
type Bip85 struct {
	masterKey *bip32.Key
}

var (
	ErrBip32IsNil = errors.New("bip32 key is nil")
)

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

// NewBip85FromXPRVString allows direct import of an existing BIP-32 xpriv string.
func NewBip85FromXPRVString(xprv string) (*Bip85, error) {
	masterKey, err := bip32.B58Deserialize(xprv)
	if err != nil {
		return nil, err
	}
	return &Bip85{masterKey: masterKey}, nil
}

// NewBip85FromBip32Key allows direct import of an existing BIP-32 key
func NewBip85FromBip32Key(bip32Key *bip32.Key) (*Bip85, error) {
	if bip32Key == nil {
		return nil, ErrBip32IsNil
	}
	return &Bip85{masterKey: bip32Key}, nil
}

func (b *Bip85) DeriveToMnemonic(language MnemonicLanguage, wordCount uint32, index uint32) (string, error) {
	if language != English {
		return "", fmt.Errorf("language is not correct")
	}

	path := []uint32{
		bip32.FirstHardenedChild + 83696968,
		bip32.FirstHardenedChild + uint32(Mnemonic),
		bip32.FirstHardenedChild + uint32(language),
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

	mac := hmac.New(sha512.New, []byte("bip-entropy-from-k"))
	mac.Write(key.Key)
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

func (b *Bip85) DeriveToXpriv(index uint32) (*bip32.Key, error) {
	path := []uint32{
		bip32.FirstHardenedChild + 83696968,
		bip32.FirstHardenedChild + uint32(Xprv),
		bip32.FirstHardenedChild + index,
	}

	key := b.masterKey
	for _, p := range path {
		var err error
		key, err = key.NewChildKey(p)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key: %w", err)
		}
	}

	if !key.IsPrivate {
		return nil, errors.New("derived key is not a private key")
	}

	mac := hmac.New(sha512.New, []byte("bip-entropy-from-k"))
	mac.Write(key.Key)
	hash := mac.Sum(nil)
	chainCode := hash[:32]
	newKey := bip32.Key{
		Version:     PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         hash[32:64],
		IsPrivate:   true,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
	}
	return &newKey, nil
}

// CountWords counts the number of words in a mnemonic phrase,
// handling leading/trailing whitespace and multiple spaces between words.
// This implementation is optimized to avoid memory allocations.
func CountWords(mnemonic string) uint {
	var count uint
	inWord := false
	for _, char := range mnemonic {
		if char == ' ' || char == '\n' || char == '\r' || char == '\t' {
			inWord = false
		} else {
			if !inWord {
				count++
				inWord = true
			}
		}
	}
	return count
}
