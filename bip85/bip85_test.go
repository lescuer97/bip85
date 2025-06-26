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

func TestFromXPRVToXPRV(t *testing.T) {
	// This is the correct xprv for the "all all all..." mnemonic.
	xprv := "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

	b, err := NewBip85FromXPRV(xprv)
	if err != nil {
		t.Fatalf("failed to create Bip85 from xprv: %v", err)
	}

	xpriv, err := b.DeriveToXpriv(0)
	if err != nil {
		t.Fatalf("failed to derive mnemonic: %v", err)
	}
	if xpriv == nil {
		t.Fatalf("xpriv is nil")
	}

	expectedXpriv := "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"

	if expectedXpriv != xpriv.B58Serialize() {
		t.Errorf("expected xpriv is not correct. %v", xpriv.B58Serialize())
	}

}
func TestFromXPRVToMnemonic(t *testing.T) {
	// This is the correct xprv for the "all all all..." mnemonic.
	xprv := "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

	b, err := NewBip85FromXPRV(xprv)
	if err != nil {
		t.Fatalf("failed to create Bip85 from xprv: %v", err)
	}

	wordCount := 12
	index := uint32(0)

	tests := []struct {
		name             string
		expectedMnemonic string
		wordCount        uint
	}{
		{"12 words", "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose", 12},
		{"18 words", "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token", 18},
		{"24 words", "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano", 24},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mnemonic, err := b.DeriveToMnemonic(English, uint32(tc.wordCount), index)
			if err != nil {
				t.Fatalf("failed to derive mnemonic: %v", err)
			}
			if mnemonic != tc.expectedMnemonic {
				t.Errorf("expected %s words, but got %d", tc.expectedMnemonic, wordCount)
			}
		})
	}
}

func TestCountWords(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
		expected uint
	}{
		{"12 words", "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose", 12},
		{"12 words with extra space", "girl  mad pet galaxy egg matter matrix prison refuse sense ordinary nose", 12},
		{"12 words with leading space", " girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose", 12},
		{"12 words with trailing space", "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose ", 12},
		{"24 words", "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano", 24},
		{"Empty string", "", 0},
		{"Just whitespace", "   ", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			count := CountWords(tc.mnemonic)
			if count != tc.expected {
				t.Errorf("expected %d words, but got %d", tc.expected, count)
			}
		})
	}
}
