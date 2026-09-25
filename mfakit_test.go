package mfakit_test

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/m1chlcz/mfakit"
)

func TestTOTPUsesRFC6238SHA1SixDigits(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	if got := mfakit.TOTPCode(secret, -1); got != "" {
		t.Fatalf("TOTPCode accepted negative counter: %q", got)
	}
	if got := mfakit.TOTPCode(secret, 1); got != "287082" {
		t.Fatalf("TOTPCode RFC vector = %q, want 287082", got)
	}
	if got := mfakit.TOTPCode(secret, 37037036); got != "081804" {
		t.Fatalf("TOTPCode later RFC vector = %q, want 081804", got)
	}
}

func TestTOTPDriftAndReplayAreBounded(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	now := time.Unix(1_700_000_000, 0)
	current := now.Unix() / mfakit.PeriodSeconds
	for _, step := range []int64{current, current - 1, current + 1} {
		matched, ok := mfakit.MatchTOTPStep(secret, mfakit.TOTPCode(secret, step), now, nil)
		if !ok || matched != step {
			t.Fatalf("MatchTOTPStep(%d) = %d/%t", step, matched, ok)
		}
		last := step
		if _, replayOK := mfakit.MatchTOTPStep(secret, mfakit.TOTPCode(secret, step), now, &last); replayOK {
			t.Fatalf("MatchTOTPStep replay accepted step %d", step)
		}
	}
	for _, invalid := range []string{"", "12345", "1234567", "１２３４５６", "12345a"} {
		if _, ok := mfakit.MatchTOTPStep(secret, invalid, now, nil); ok {
			t.Fatalf("MatchTOTPStep accepted %q", invalid)
		}
	}
	if _, ok := mfakit.MatchTOTPStep(secret, mfakit.TOTPCode(secret, current+2), now, nil); ok {
		t.Fatal("MatchTOTPStep accepted code outside drift window")
	}
}

func TestEnvelopeBindsVersionKeyIDAndUser(t *testing.T) {
	t.Parallel()
	key := bytesSequence(mfakit.KeyBytes, 1)
	userID := uuid.MustParse("01912345-6789-7abc-8def-0123456789ab")
	secret := bytesSequence(mfakit.SecretBytes, 33)
	envelope, err := mfakit.EncryptSecret(7, key, userID, secret)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if len(envelope) != 2+12+len(secret)+16 || envelope[0] != 1 || envelope[1] != 7 {
		t.Fatalf("envelope shape = len %d prefix %v", len(envelope), envelope[:2])
	}
	decrypted, err := mfakit.DecryptSecret(map[byte][]byte{7: key}, userID, envelope)
	if err != nil || string(decrypted) != string(secret) {
		t.Fatalf("DecryptSecret = %x, %v", decrypted, err)
	}
	if _, err := mfakit.DecryptSecret(map[byte][]byte{7: key}, uuid.New(), envelope); err == nil {
		t.Fatal("DecryptSecret accepted a different user")
	}
	if _, err := mfakit.DecryptSecret(map[byte][]byte{8: key}, userID, envelope); err == nil {
		t.Fatal("DecryptSecret accepted an unknown key ID")
	}
	tamperedKeyID := append([]byte(nil), envelope...)
	tamperedKeyID[1] = 8
	if _, err := mfakit.DecryptSecret(map[byte][]byte{7: key, 8: key}, userID, tamperedKeyID); err == nil {
		t.Fatal("DecryptSecret accepted a tampered key ID")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := mfakit.DecryptSecret(map[byte][]byte{7: key}, userID, tampered); err == nil {
		t.Fatal("DecryptSecret accepted a tampered ciphertext")
	}
}

func TestRecoveryCodesAreCanonicalAndHashable(t *testing.T) {
	t.Parallel()
	random := strings.NewReader(string(bytesSequence(mfakit.RecoveryCodeCount*mfakit.RecoveryCodeBytes, 9)))
	codes, hashes, err := mfakit.NewRecoveryCodes(random)
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("recovery counts = %d/%d", len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for index, display := range codes {
		canonical, err := mfakit.CanonicalRecoveryCode(strings.ToLower(display))
		if err != nil {
			t.Fatalf("CanonicalRecoveryCode(%q): %v", display, err)
		}
		if strings.Contains(canonical, "-") ||
			len(canonical) != base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(mfakit.RecoveryCodeBytes) {
			t.Fatalf("canonical recovery code = %q", canonical)
		}
		if seen[canonical] || hashes[index] != sha256.Sum256([]byte(canonical)) {
			t.Fatalf("duplicate or wrong recovery hash for %q", canonical)
		}
		seen[canonical] = true
	}
	for _, invalid := range []string{"", "INVALID!", strings.Repeat("A", 25), strings.Repeat("A", 27)} {
		if _, err := mfakit.CanonicalRecoveryCode(invalid); err == nil {
			t.Fatalf("CanonicalRecoveryCode accepted %q", invalid)
		}
	}
}

func TestSecretKeyIDAndInvalidInput(t *testing.T) {
	t.Parallel()
	secret, err := mfakit.NewSecret(strings.NewReader(string(bytesSequence(mfakit.SecretBytes, 1))))
	if err != nil || len(secret) != mfakit.SecretBytes {
		t.Fatalf("NewSecret = %x, %v", secret, err)
	}
	if _, err := mfakit.NewSecret(nil); err == nil {
		t.Fatal("NewSecret accepted a nil source")
	}
	if id, err := mfakit.ParseKeyID("", 3); err != nil || id != 3 {
		t.Fatalf("ParseKeyID empty = %d, %v", id, err)
	}
	if _, err := mfakit.ParseKeyID("", 0); err == nil {
		t.Fatal("ParseKeyID accepted a zero fallback")
	}
	if id, err := mfakit.ParseKeyID("7", 3); err != nil || id != 7 {
		t.Fatalf("ParseKeyID value = %d, %v", id, err)
	}
	for _, invalid := range []string{"0", "256", "-1", "abc"} {
		if _, err := mfakit.ParseKeyID(invalid, 3); err == nil {
			t.Fatalf("ParseKeyID accepted %q", invalid)
		}
	}
	key := bytesSequence(mfakit.KeyBytes, 1)
	userID := uuid.New()
	valid := bytesSequence(mfakit.SecretBytes, 1)
	if _, err := mfakit.EncryptSecret(0, key, userID, valid); err == nil {
		t.Fatal("EncryptSecret accepted key ID 0")
	}
	if _, err := mfakit.EncryptSecret(1, key[:16], userID, valid); err == nil {
		t.Fatal("EncryptSecret accepted a short key")
	}
	if _, err := mfakit.EncryptSecret(1, key, userID, []byte("short")); err == nil {
		t.Fatal("EncryptSecret accepted a short secret")
	}
	if _, err := mfakit.DecryptSecret(map[byte][]byte{1: key}, userID, []byte{2, 1}); err == nil {
		t.Fatal("DecryptSecret accepted an invalid envelope")
	}
}

func bytesSequence(length, start int) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = byte(start + index)
	}
	return value
}
