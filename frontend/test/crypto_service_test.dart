import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart';
import 'package:remote_pin_selection_demo/services/crypto_service.dart';

/// Known-answer test. The expected values were produced by an independent Go
/// implementation of the same profile that was validated against AWS Payment
/// Cryptography. Matching them shows this client derives the same key and PIN
/// block that the service will.
void main() {
  const appPrivHex =
      '11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff';
  const agreementPubHex =
      '04fcba1aa46a313860412b39aed568d7001364a643f0ababcd734f62b575c7eb5a'
      '2915d6c495f2c5c07bf0189572017c032bcc3513b7bd5f6e1f771ae075b8ca24';
  // Fixed KDF input for the vector. It contains a zero byte, which the service
  // would reject; real requests use newSharedInformation().
  const sharedInfoHex =
      'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';
  const expectedSharedSecret =
      'd0a5c5100acd503e1d1d3e98a478446c33e121f14a59795bc3f141b6ff89f7fe';
  const expectedTdesKey = '5c2189344b8ae135cdf158f607b03362';
  const expectedClearBlock = '041235dcba9876fe';
  const expectedEncryptedBlock = '1539A04C33BEDB94';

  final crypto = CryptoService();
  final curve = ECCurve_secp256r1();
  final appPrivateKey = ECPrivateKey(_bytesToBig(_hex(appPrivHex)), curve);
  final agreementPublicKey =
      ECPublicKey(curve.curve.decodePoint(_hex(agreementPubHex)), curve);

  test('ECDH, KDF, and ISO-0 steps match the known-answer vector', () {
    final secret = crypto.ecdhSharedSecret(appPrivateKey, agreementPublicKey);
    final key = crypto.concatKdfSha512(secret, _hex(sharedInfoHex), 16);
    final block = crypto.iso0PinBlock('1234', '4000123456789010');

    expect(_toHex(secret), expectedSharedSecret);
    expect(_toHex(key), expectedTdesKey);
    expect(_toHex(block), expectedClearBlock);
  });

  test('encryptPinWithPublicKey returns only the encrypted block and KDF input',
      () {
    final encrypted = crypto.encryptPinWithPublicKey(
      appPrivateKey: appPrivateKey,
      agreementPublicKey: agreementPublicKey,
      pin: '1234',
      pan: '4000123456789010',
      sharedInformation: _hex(sharedInfoHex),
    );

    expect(encrypted.encryptedPinBlockHex, expectedEncryptedBlock);
    expect(encrypted.sharedInformationHex, sharedInfoHex.toUpperCase());
  });

  test('newSharedInformation is 32 fresh bytes with no zero byte', () {
    final first = crypto.newSharedInformation();
    final second = crypto.newSharedInformation();

    expect(first, hasLength(32));
    expect(first.contains(0), isFalse);
    expect(first, isNot(equals(second)));
    // Repeat to make a zero byte statistically near-certain if the range
    // were wrong (1000 * 32 draws).
    for (var i = 0; i < 1000; i++) {
      expect(crypto.newSharedInformation().contains(0), isFalse);
    }
  });

  test('generateEphemeralKeyAndCsr creates a P-256 CSR', () {
    final key = crypto.generateEphemeralKeyAndCsr();

    expect(key.csrPem, contains('CERTIFICATE REQUEST'));
    expect(key.privateKey.parameters!.domainName, 'prime256v1');
  });

  test('iso0PinBlock rejects malformed input', () {
    expect(() => crypto.iso0PinBlock('12', '4000123456789010'),
        throwsArgumentError);
    expect(() => crypto.iso0PinBlock('1234', '4000'), throwsArgumentError);
  });
}

Uint8List _hex(String h) => Uint8List.fromList(List<int>.generate(
    h.length ~/ 2, (i) => int.parse(h.substring(i * 2, i * 2 + 2), radix: 16)));

String _toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

BigInt _bytesToBig(Uint8List b) =>
    b.fold(BigInt.zero, (r, x) => (r << 8) | BigInt.from(x));
