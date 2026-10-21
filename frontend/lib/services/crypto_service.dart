import 'dart:math';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:meta/meta.dart' show visibleForTesting;
import 'package:pointycastle/export.dart';

/// The encrypted PIN block and the KDF input needed to translate it. This is
/// everything the app sends; the clear PIN, the ephemeral private key, the ECDH
/// shared secret, and the derived key never leave [CryptoService].
class EncryptedPin {
  const EncryptedPin({
    required this.encryptedPinBlockHex,
    required this.sharedInformationHex,
  });

  final String encryptedPinBlockHex;
  final String sharedInformationHex;
}

/// An ephemeral P-256 key pair and a CSR for its public key. The backend has
/// AWS Private CA sign the CSR; the private key stays in the app.
class EphemeralKey {
  EphemeralKey({required this.privateKey, required this.csrPem});

  final ECPrivateKey privateKey;
  final String csrPem;
}

/// Client-side cryptography for remote PIN selection.
///
/// The parameters form the interoperability profile from the blog post and
/// must match the backend's `apc` package exactly:
///
/// | Property                | Value                               |
/// |-------------------------|-------------------------------------|
/// | ECDH key agreement      | P-256 (`ECC_NIST_P256`)             |
/// | Key derivation          | NIST SP 800-56C ConcatKDF, SHA-512  |
/// | Temporary symmetric key | TDES double-length, 16 bytes        |
/// | PIN block               | ISO 9564 Format 0, TDES-ECB         |
/// | SharedInformation       | 32 fresh random bytes, no 0x00      |
class CryptoService {
  /// Step 1: create a fresh key pair and CSR for one operation. Never reuse
  /// the key pair: each operation gets its own ECDH-derived key.
  EphemeralKey generateEphemeralKeyAndCsr() {
    final pair = CryptoUtils.generateEcKeyPair(curve: 'prime256v1');
    final privateKey = pair.privateKey as ECPrivateKey;
    final csrPem = X509Utils.generateEccCsrPem(
      {'CN': 'remote-pin-demo-app'},
      privateKey,
      pair.publicKey as ECPublicKey,
    );
    return EphemeralKey(privateKey: privateKey, csrPem: csrPem);
  }

  /// Step 2: fresh SharedInformation for the KDF. AWS Payment Cryptography
  /// requires hexadecimal data with no zero bytes, and it should not be
  /// reused, so each byte is drawn from 1-255.
  Uint8List newSharedInformation() {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(255) + 1),
    );
  }

  /// Step 3: encrypt the PIN for AWS Payment Cryptography.
  ///
  /// [agreementCertificatePem] is the certificate of the service's ECDH
  /// key-agreement key, returned by `POST /api/operations`.
  EncryptedPin encryptPin({
    required ECPrivateKey appPrivateKey,
    required String agreementCertificatePem,
    required String pin,
    required String pan,
    required Uint8List sharedInformation,
  }) {
    // Extract the agreement public key from the certificate's
    // SubjectPublicKeyInfo.
    final cert = X509Utils.x509CertificateFromPem(agreementCertificatePem);
    final spkiHex = cert.tbsCertificate!.subjectPublicKeyInfo.bytes!;
    final agreementPublicKey = CryptoUtils.ecPublicKeyFromDerBytes(
      _hexToBytes(spkiHex),
    );
    return encryptPinWithPublicKey(
      appPrivateKey: appPrivateKey,
      agreementPublicKey: agreementPublicKey,
      pin: pin,
      pan: pan,
      sharedInformation: sharedInformation,
    );
  }

  /// Same as [encryptPin] with the agreement public key supplied directly.
  EncryptedPin encryptPinWithPublicKey({
    required ECPrivateKey appPrivateKey,
    required ECPublicKey agreementPublicKey,
    required String pin,
    required String pan,
    required Uint8List sharedInformation,
  }) {
    // ECDH: the app's private key and the service's public key produce the
    // same shared secret that Payment Cryptography computes from its private
    // key and the public key in the app's certificate.
    final sharedSecret = ecdhSharedSecret(appPrivateKey, agreementPublicKey);

    // KDF: turn the shared secret into a 16-byte TDES key. SharedInformation
    // is sent to the backend so the service can derive the same key.
    final tdesKey = concatKdfSha512(sharedSecret, sharedInformation, 16);

    // Build the ISO-0 PIN block and encrypt it under the derived key.
    final clearBlock = iso0PinBlock(pin, pan);
    final encryptedBlock = _tdesEcbEncrypt(tdesKey, clearBlock);

    return EncryptedPin(
      encryptedPinBlockHex: _hex(encryptedBlock).toUpperCase(),
      sharedInformationHex: _hex(sharedInformation).toUpperCase(),
    );
  }

  /// ECDH on P-256. Returns the shared x-coordinate as 32 big-endian bytes.
  @visibleForTesting
  Uint8List ecdhSharedSecret(ECPrivateKey privateKey, ECPublicKey publicKey) {
    final agreement = ECDHBasicAgreement()..init(privateKey);
    return _fixedWidth32(agreement.calculateAgreement(publicKey));
  }

  /// NIST SP 800-56C one-step KDF (ConcatKDF) with SHA-512, which is what
  /// Payment Cryptography calls `NIST_SP800`. Output is
  /// SHA512(counter || Z || SharedInformation) for counter = 1, 2, ...,
  /// concatenated and truncated to [length] bytes.
  @visibleForTesting
  Uint8List concatKdfSha512(Uint8List z, Uint8List sharedInfo, int length) {
    final digest = SHA512Digest();
    final out = BytesBuilder();
    for (var counter = 1; out.length < length; counter++) {
      final counterBytes = Uint8List(4)
        ..buffer.asByteData().setUint32(0, counter);
      digest
        ..reset()
        ..update(counterBytes, 0, 4)
        ..update(z, 0, z.length)
        ..update(sharedInfo, 0, sharedInfo.length);
      final block = Uint8List(digest.digestSize);
      digest.doFinal(block, 0);
      out.add(block);
    }
    return Uint8List.fromList(out.toBytes().sublist(0, length));
  }

  /// ISO 9564 Format 0 PIN block: PIN field XOR PAN field.
  ///
  ///   PIN field: 0 | PIN length | PIN digits | padded with F to 16 nibbles
  ///   PAN field: 0000 | the 12 rightmost PAN digits, excluding the check digit
  ///
  /// This is why the PAN is needed both here and in TranslatePinData.
  @visibleForTesting
  Uint8List iso0PinBlock(String pin, String pan) {
    if (!RegExp(r'^\d{4,12}$').hasMatch(pin)) {
      throw ArgumentError('PIN must be 4-12 digits');
    }
    if (!RegExp(r'^\d{13,19}$').hasMatch(pan)) {
      throw ArgumentError('PAN must be 13-19 digits');
    }
    final pinField = '0${pin.length.toRadixString(16)}$pin'.padRight(16, 'F');
    final panField = '0000${pan.substring(pan.length - 13, pan.length - 1)}';
    final pinBytes = _hexToBytes(pinField);
    final panBytes = _hexToBytes(panField);
    return Uint8List.fromList(
      List<int>.generate(8, (i) => pinBytes[i] ^ panBytes[i]),
    );
  }

  /// TDES-ECB on one 8-byte block. A double-length key K1|K2 is used as
  /// K1|K2|K1.
  Uint8List _tdesEcbEncrypt(Uint8List key16, Uint8List block8) {
    final key24 = Uint8List(24)
      ..setRange(0, 16, key16)
      ..setRange(16, 24, key16.sublist(0, 8));
    final cipher = ECBBlockCipher(DESedeEngine())
      ..init(true, KeyParameter(key24));
    final out = Uint8List(8);
    cipher.processBlock(block8, 0, out, 0);
    return out;
  }

  Uint8List _fixedWidth32(BigInt value) {
    final out = Uint8List(32);
    var remaining = value;
    for (var i = 31; i >= 0; i--) {
      out[i] = (remaining & BigInt.from(0xff)).toInt();
      remaining = remaining >> 8;
    }
    return out;
  }

  String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  Uint8List _hexToBytes(String hex) => Uint8List.fromList(
        List<int>.generate(
          hex.length ~/ 2,
          (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
        ),
      );
}
