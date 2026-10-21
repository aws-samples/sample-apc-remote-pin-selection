# Security

## Reporting a security issue

If you discover a potential security issue in this project, notify AWS
Security through the
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Do **not** create a public GitHub issue.

Do not include cardholder data, PINs, AWS credentials, private keys, or
account-specific resource identifiers in a report.

## Demo limitations

This repository demonstrates a cryptographic flow. It is not a production
payment system and makes no PCI DSS or PCI PIN compliance claim. In particular:

- **No authentication.** Any caller can begin an operation for any PAN. A
  production issuer binds each operation to an authenticated cardholder
  session and checks card eligibility with the banking system first.
- **In-memory operations.** Single-use operation state lives in one backend
  process. Production state must be shared across instances.
- **Processor stand-in.** PVV generation, verifier storage, and PIN
  verification belong to the banking system or processor. The demo's stand-in
  has no retry counter or lockout, and it stores the PAN in cleartext as the
  DynamoDB key. Use synthetic PANs only.
- **No agreement-certificate validation.** The app trusts the agreement
  certificate the backend returns. A production app pins the expected
  Payment Cryptography agreement key or its issuing CA and checks validity;
  otherwise whoever controls the network or the backend can substitute a key
  and read PINs.
- **Client environment.** The clear PIN, the ephemeral private key, the ECDH
  shared secret, and the derived key exist briefly in the app's memory.
  Managed runtimes do not guarantee memory zeroization, and web and mobile
  channels each need their own controls (script integrity, attestation, and
  so on).
- **Local-development defaults.** The backend binds to loopback and allows
  only the local web app origins through CORS, which restricts browsers but
  is not authentication. The frontend and backend use plain HTTP on
  localhost, and no infrastructure, network isolation, rate limiting, web
  security headers, monitoring, or audit controls are provided. Base images
  and the Flutter SDK are pinned by tag, not digest.
- **Sensitive demo logging.** `DEMO_LOG_SENSITIVE_VALUES=true` prints synthetic
  PANs, encrypted PIN blocks, and PVVs. Never enable it with real data.

## Secrets

`backend/.env` holds your resource identifiers and is ignored by Git. Never
commit it, AWS credentials, or private keys.
