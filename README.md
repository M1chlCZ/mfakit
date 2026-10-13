# mfakit

TOTP codes, otpauth provisioning URIs, an encrypted secret envelope, and
recovery codes for Go services.

## Features

- RFC 6238 TOTP with HMAC-SHA-1, six digits, and a 30-second period.
- A drift window of one step in each direction, with a replay guard.
- An `otpauth://totp/` provisioning URI with the issuer, the account, and the base32 secret for authenticator apps.
- An AES-256-GCM envelope with a version byte, a key ID, a random nonce, and an AAD binding to the user ID.
- Ten recovery codes with 16 random bytes each. Store only the SHA-256 hashes.

## Install

```
go get github.com/m1chlcz/mfakit
```

## Parameters

| Item | Value |
| --- | --- |
| Secret | 20 bytes |
| Encryption key | 32 bytes |
| Code | 6 digits |
| Period | 30 seconds |
| Drift | one step in each direction |
| Recovery codes | 10 |
| Recovery code | 16 bytes |

## Usage

```go
secret, err := mfakit.NewSecret(rand.Reader)
envelope, err := mfakit.EncryptSecret(keyID, key, userID, secret)
secret, err = mfakit.DecryptSecret(keys, userID, envelope)
code := mfakit.TOTPCode(secret, time.Now().Unix()/mfakit.PeriodSeconds)
step, ok := mfakit.MatchTOTPStep(secret, input, time.Now(), lastUsed)
uri, err := mfakit.OTPAuthURI(issuer, account, secret)
codes, hashes, err := mfakit.NewRecoveryCodes(rand.Reader)
canonical, err := mfakit.CanonicalRecoveryCode(input)
```

## Notes

- Generate the encryption key with a random source. Keep it in a secret manager.
- Rotate a key with a new ID. `DecryptSecret` reads the ID from the envelope.
- Store only the recovery hashes. Compare a canonical code with `subtle.ConstantTimeCompare`.
- Store the matched step and pass it as `lastUsed` on the next check. The package cannot store it for you.
- `OTPAuthURI` returns the provisioning URI only. Add the QR step in the caller; the package keeps no QR dependency.
- The package does not log secrets and does not send data anywhere.

## Development

```
go test -race ./...
```

## License

MIT. See `LICENSE`.
