# river-egress

River AI signup lane on GitHub Actions — fresh device + fresh IP per run.

## Modes
- `mailtest` — verifies the Gmail read rail works from the runner (no signup).
- `signup` — ONE account per run: signup → email OTP (Gmail rail) → console → $25 grant → API key → live API test.

## Doctrine
- Dispatch payload (email/persona) is AES-256-GCM ciphertext; key = sha256(ENC_KEY secret) — only holder of the secret can encrypt/decrypt.
- Password generated in-run; nothing sensitive in inputs, logs, or commit messages.
- Results (account JSON + screenshots) are envelope-encrypted AES-256-GCM + RSA-4096-OAEP against `river-public.pem`; only the local private key can decrypt.
- This public repo contains scripts + ciphertext only.

## Secrets
- `ENC_KEY` — payload decryption key.
- `GMAIL_CK` — base64 of the mail-reader cookie jar (rotated per wave).
