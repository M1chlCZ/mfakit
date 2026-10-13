package mfakit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP mandates HMAC-SHA-1 for compatibility.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const (
	SecretBytes       = 20
	KeyBytes          = 32
	CodeDigits        = 6
	PeriodSeconds     = 30
	RecoveryCodeCount = 10
	RecoveryCodeBytes = 16
)

const (
	envelopeVersion   = byte(1)
	dynamicOffsetMask = byte(0x0f)
	dynamicValueMask  = uint32(0x7fffffff)
	codeModulus       = 1_000_000
	otpAuthAlgorithm  = "SHA1"
)

const aadDomain = "mfakit/totp/v1"

// NewSecret returns a random TOTP secret.
func NewSecret(random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, errors.New("random source is required")
	}
	secret := make([]byte, SecretBytes)
	if _, err := io.ReadFull(random, secret); err != nil {
		return nil, errors.New("generate secret")
	}
	return secret, nil
}

// TOTPCode returns the RFC 6238 six-digit code (HMAC-SHA-1) for a time step. A
// negative step returns an empty string.
func TOTPCode(secret []byte, step int64) string {
	if step < 0 {
		return ""
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & dynamicOffsetMask
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & dynamicValueMask
	return fmt.Sprintf("%06d", value%codeModulus)
}

// MatchTOTPStep checks a code against the current step and one step in each
// direction. A non-nil lastUsed value rejects a replay of an earlier step.
func MatchTOTPStep(secret []byte, code string, now time.Time, lastUsed *int64) (int64, bool) {
	if len(code) != CodeDigits {
		return 0, false
	}
	for index := range code {
		if code[index] < '0' || code[index] > '9' {
			return 0, false
		}
	}
	current := now.Unix() / PeriodSeconds
	for _, step := range []int64{current, current - 1, current + 1} {
		if lastUsed != nil && step <= *lastUsed {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(TOTPCode(secret, step))) == 1 {
			return step, true
		}
	}
	return 0, false
}

// OTPAuthURI returns an otpauth TOTP provisioning URI for authenticator apps.
// The label carries the trimmed issuer and account separated by a colon, and
// the issuer parameter repeats the issuer. The secret parameter is the base32
// encoding without padding. The algorithm, digits, and period parameters come
// from the package parameters (SHA-1, CodeDigits digits, PeriodSeconds
// seconds). The secret must be SecretBytes long. The issuer and account must
// not be empty and must not contain control characters. Render the QR code in
// the caller: this package keeps no QR dependency.
func OTPAuthURI(issuer, account string, secret []byte) (string, error) {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" {
		return "", errors.New("issuer is required")
	}
	if account == "" {
		return "", errors.New("account is required")
	}
	if hasControlCharacter(issuer) {
		return "", errors.New("issuer contains control characters")
	}
	if hasControlCharacter(account) {
		return "", errors.New("account contains control characters")
	}
	if len(secret) != SecretBytes {
		return "", fmt.Errorf("secret must be %d bytes", SecretBytes)
	}
	escapedIssuer := escapeURIPart(issuer)
	escapedAccount := escapeURIPart(account)
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return "otpauth://totp/" + escapedIssuer + ":" + escapedAccount +
		"?secret=" + encodedSecret +
		"&issuer=" + escapedIssuer +
		"&algorithm=" + otpAuthAlgorithm +
		"&digits=" + strconv.Itoa(CodeDigits) +
		"&period=" + strconv.Itoa(PeriodSeconds), nil
}

func hasControlCharacter(value string) bool {
	for _, char := range value {
		if unicode.IsControl(char) {
			return true
		}
	}
	return false
}

func escapeURIPart(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(len(value))
	for index := 0; index < len(value); index++ {
		char := value[index]
		if isURIUnreserved(char) {
			escaped.WriteByte(char)
			continue
		}
		escaped.WriteByte('%')
		escaped.WriteByte(hexDigits[char>>4])
		escaped.WriteByte(hexDigits[char&0x0f])
	}
	return escaped.String()
}

func isURIUnreserved(char byte) bool {
	switch {
	case 'a' <= char && char <= 'z', 'A' <= char && char <= 'Z', '0' <= char && char <= '9':
		return true
	case char == '-', char == '.', char == '_', char == '~':
		return true
	}
	return false
}

// EncryptSecret wraps a TOTP secret in an AES-256-GCM envelope. The envelope
// holds the version byte, the key ID, the random nonce, and the ciphertext.
func EncryptSecret(keyID byte, key []byte, userID uuid.UUID, secret []byte) ([]byte, error) {
	if keyID == 0 || len(key) != KeyBytes || len(secret) != SecretBytes {
		return nil, errors.New("invalid TOTP encryption input")
	}
	aead, err := envelopeAEAD(key)
	if err != nil {
		return nil, err
	}
	prefix := []byte{envelopeVersion, keyID}
	sealed := aead.Seal(prefix, nil, secret, aad(prefix, userID)) //nolint:gosec // NewGCMWithRandomNonce requires a nil nonce.
	return sealed, nil
}

// DecryptSecret opens an envelope with one of the keys. The key ID in the
// envelope selects the key.
func DecryptSecret(keys map[byte][]byte, userID uuid.UUID, envelope []byte) ([]byte, error) {
	if len(envelope) < 2 || envelope[0] != envelopeVersion || envelope[1] == 0 {
		return nil, errors.New("invalid TOTP envelope")
	}
	key, ok := keys[envelope[1]]
	if !ok || len(key) != KeyBytes {
		return nil, errors.New("unknown TOTP encryption key")
	}
	aead, err := envelopeAEAD(key)
	if err != nil {
		return nil, err
	}
	secret, err := aead.Open(nil, nil, envelope[2:], aad(envelope[:2], userID))
	if err != nil || len(secret) != SecretBytes {
		return nil, errors.New("invalid TOTP envelope")
	}
	return secret, nil
}

func envelopeAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid TOTP encryption key")
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, errors.New("initialize TOTP encryption")
	}
	return aead, nil
}

func aad(prefix []byte, userID uuid.UUID) []byte {
	result := make([]byte, 0, len(aadDomain)+len(prefix)+len(userID))
	result = append(result, aadDomain...)
	result = append(result, prefix...)
	result = append(result, userID[:]...)
	return result
}

// NewRecoveryCodes returns one-time recovery codes in display form and their
// SHA-256 hashes. Store only the hashes.
func NewRecoveryCodes(random io.Reader) ([]string, [][sha256.Size]byte, error) {
	if random == nil {
		return nil, nil, errors.New("recovery random source is required")
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	codes := make([]string, 0, RecoveryCodeCount)
	hashes := make([][sha256.Size]byte, 0, RecoveryCodeCount)
	seen := make(map[string]struct{}, RecoveryCodeCount)
	for len(codes) < RecoveryCodeCount {
		var raw [RecoveryCodeBytes]byte
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return nil, nil, errors.New("generate recovery codes")
		}
		canonical := encoding.EncodeToString(raw[:])
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		codes = append(codes, DisplayRecoveryCode(canonical))
		hashes = append(hashes, sha256.Sum256([]byte(canonical)))
	}
	return codes, hashes, nil
}

// CanonicalRecoveryCode normalizes user input. It accepts lower case, upper
// case, and grouped input with dashes.
func CanonicalRecoveryCode(value string) (string, error) {
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	upper := strings.ToUpper(value)
	canonical := upper
	if strings.Contains(upper, "-") {
		if DisplayRecoveryCode(strings.ReplaceAll(upper, "-", "")) != upper {
			return "", errors.New("invalid recovery code")
		}
		canonical = strings.ReplaceAll(upper, "-", "")
	}
	decoded, err := encoding.DecodeString(canonical)
	if err != nil || len(decoded) != RecoveryCodeBytes || encoding.EncodeToString(decoded) != canonical {
		return "", errors.New("invalid recovery code")
	}
	return canonical, nil
}

// DisplayRecoveryCode groups a canonical code in blocks of four characters.
func DisplayRecoveryCode(canonical string) string {
	if canonical == "" {
		return ""
	}
	var output strings.Builder
	output.Grow(len(canonical) + len(canonical)/4)
	for index, char := range canonical {
		if index > 0 && index%4 == 0 {
			output.WriteByte('-')
		}
		output.WriteRune(char)
	}
	return output.String()
}

// ParseKeyID reads a key ID from a decimal string. An empty string returns the
// fallback value.
func ParseKeyID(value string, fallback byte) (byte, error) {
	if value == "" {
		if fallback == 0 {
			return 0, errors.New("key ID must be a number from 1 to 255")
		}
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 8)
	if err != nil || parsed == 0 {
		return 0, errors.New("key ID must be a number from 1 to 255")
	}
	return byte(parsed), nil
}
