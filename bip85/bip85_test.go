
package bip85

import (
	"strings"
	"testing"
)

func TestNonEnglishMnemonic(t *testing.T) {
	// A valid Spanish mnemonic
	spanishMnemonic := "taza sitio punto rostro esfera oeste garza primo azar paella escolta exagerar"
	_, err := NewBip85FromMnemonic(spanishMnemonic, "")
	if err == nil {
		t.Fatal("expected an error for non-English mnemonic, but got nil")
	}

	expectedError := "mnemonic is not valid or not in English"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("expected error message to contain %q, but got %q", expectedError, err.Error())
	}
}

func TestFromXPRV(t *testing.T) {
	// This is the correct xprv for the "all all all..." mnemonic.
	xprv := "xprv9s21ZrQH143K2rbkN6QpF6ZB3QQcyJA6aYbagMp6i8y831VVvpfcWNWqg5DM6GxSn66UDQUrgRgQEsLPZJC3APkPsQjxB7ndNMgj5R5HLmo"

	b, err := NewBip85FromXPRV(xprv)
	if err != nil {
		t.Fatalf("failed to create Bip85 from xprv: %v", err)
	}

	wordCount := 12
	index := uint32(0)
	expectedMnemonic := "dragon great exhaust dice owner element tank canal cliff brand vibrant twelve"

	mnemonic, err := b.DeriveMnemonic(wordCount, index)
	if err != nil {
		t.Fatalf("failed to derive mnemonic: %v", err)
	}

	if mnemonic != expectedMnemonic {
		t.Errorf("expected mnemonic %q, but got %q", expectedMnemonic, mnemonic)
	}
}
