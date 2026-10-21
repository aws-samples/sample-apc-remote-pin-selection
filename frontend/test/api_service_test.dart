import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:pointycastle/export.dart';
import 'package:remote_pin_selection_demo/services/api_service.dart';
import 'package:remote_pin_selection_demo/services/crypto_service.dart';

/// Crypto stub: the HTTP sequence is under test here, not the cryptography.
class FakeCrypto extends CryptoService {
  @override
  EphemeralKey generateEphemeralKeyAndCsr() => EphemeralKey(
        privateKey: ECPrivateKey(BigInt.one, ECCurve_secp256r1()),
        csrPem: 'csr-pem',
      );

  @override
  Uint8List newSharedInformation() => Uint8List.fromList(List.filled(32, 0xab));

  @override
  EncryptedPin encryptPin({
    required ECPrivateKey appPrivateKey,
    required String agreementCertificatePem,
    required String pin,
    required String pan,
    required Uint8List sharedInformation,
  }) {
    expect(agreementCertificatePem, 'agreement-pem');
    return const EncryptedPin(
      encryptedPinBlockHex: '0011223344556677',
      sharedInformationHex: 'ABAB',
    );
  }
}

void main() {
  const operationId = '0123456789abcdef0123456789abcdef';

  test('prepareEnvelope binds the CSR and envelope to one operation', () async {
    final requests = <http.Request>[];
    final service = ApiService(
      baseUrl: 'http://backend',
      client: MockClient((request) async {
        requests.add(request);
        switch (request.url.path) {
          case '/api/operations':
            return http.Response(
                jsonEncode({
                  'operation_id': operationId,
                  'expires_at': '2026-01-01T00:05:00Z',
                  'agreement_certificate_pem': 'agreement-pem',
                }),
                200);
          case '/api/csr-sign':
            return http.Response(
                jsonEncode({'certificate_pem': 'client-pem'}), 200);
        }
        return http.Response('{}', 404);
      }),
    );

    final envelope = await service.prepareEnvelope(
      crypto: FakeCrypto(),
      type: PinOperationType.set,
      pan: '4000123456789010',
      pin: '1234',
    );

    expect(
        requests.map((r) => r.url.path), ['/api/operations', '/api/csr-sign']);
    expect(jsonDecode(requests[0].body),
        {'type': 'pin-set', 'pan': '4000123456789010'});
    expect(jsonDecode(requests[1].body),
        {'operation_id': operationId, 'csr_pem': 'csr-pem'});
    expect(envelope.toJson(), {
      'operation_id': operationId,
      'pan': '4000123456789010',
      'encrypted_pin_block': '0011223344556677',
      'client_cert_pem': 'client-pem',
      'shared_information': 'ABAB',
    });
  });

  const envelope = PinEnvelope(
    operationId: operationId,
    pan: '4000123456789010',
    encryptedPinBlock: '0011223344556677',
    clientCertificatePem: 'client-pem',
    sharedInformation: 'ABAB',
  );

  test('setPin posts the envelope to the set endpoint', () async {
    late http.Request captured;
    final service = ApiService(
      client: MockClient((request) async {
        captured = request;
        return http.Response('{"success":true,"version":2}', 200);
      }),
    );

    final response = await service.setPin(envelope);

    expect(captured.url.path, '/api/pin/set');
    expect(jsonDecode(captured.body), envelope.toJson());
    expect(response.version, 2);
  });

  test('validatePin posts the envelope to the validate endpoint', () async {
    late http.Request captured;
    final service = ApiService(
      client: MockClient((request) async {
        captured = request;
        return http.Response('{"success":true,"valid":false}', 200);
      }),
    );

    final response = await service.validatePin(envelope);

    expect(captured.url.path, '/api/pin/validate');
    expect(response.valid, isFalse);
  });

  test('a rejected operation surfaces as an error', () async {
    final service = ApiService(
      client: MockClient((_) async => http.Response(
          '{"error":"operation is not valid; start a new operation"}', 409)),
    );

    expect(service.setPin(envelope), throwsException);
  });
}
