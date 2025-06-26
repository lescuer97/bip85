
package bip85

import (
	"testing"
)

func TestBIP85_CorrectMasterKey(t *testing.T) {
	mnemonic := "all all all all all all all all all all all all"
	passphrase := ""

	b, err := NewFromMnemonic(mnemonic, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	// Test vectors from a known-good implementation
	tests := []struct {
		wordCount       int
		index           uint32
		expectedMnemonic string
	}{
		{
			12,
			0,
			"dragon great exhaust dice owner element tank canal cliff brand vibrant twelve",
		},
		{
			18,
			0,
			"affair dolphin door couple swarm fiscal below thunder crane box follow suffer minute jungle pipe digital december cereal",
		},
		{
			24,
			0,
			"cook tower daring garage salt transfer pipe expand design sadness noise hello coffee mechanic barely sorry midnight jungle around dinner maze survey pretty review",
		},
	}

	for _, tc := range tests {
		mnemonic, err := b.DeriveMnemonic(tc.wordCount, tc.index)
		if err != nil {
			t.Fatal(err)
		}
		if mnemonic != tc.expectedMnemonic {
			t.Errorf("expected mnemonic %q, but got %q", tc.expectedMnemonic, mnemonic)
		}
	}
}
