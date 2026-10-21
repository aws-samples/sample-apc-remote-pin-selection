import 'dart:convert';

import 'package:http/http.dart' as http;

import 'crypto_service.dart';

/// The PIN operations the backend supports.
enum PinOperationType {
  set('pin-set', '/api/pin/set'),
  validate('pin-validate', '/api/pin/validate');

  const PinOperationType(this.wireName, this.submitPath);

  final String wireName;
  final String submitPath;
}

/// The encrypted PIN envelope sent to the backend. It contains no clear PIN
/// and no key material that could recover it.
class PinEnvelope {
  const PinEnvelope({
    required this.operationId,
    required this.pan,
    required this.encryptedPinBlock,
    required this.clientCertificatePem,
    required this.sharedInformation,
  });

  final String operationId;
  final String pan;
  final String encryptedPinBlock;
  final String clientCertificatePem;
  final String sharedInformation;

  Map<String, String> toJson() => {
        'operation_id': operationId,
        'pan': pan,
        'encrypted_pin_block': encryptedPinBlock,
        'client_cert_pem': clientCertificatePem,
        'shared_information': sharedInformation,
      };
}

class SetPinResponse {
  const SetPinResponse({required this.version});

  /// Version of the processor's verifier record; increments on every reset.
  final int version;

  factory SetPinResponse.fromJson(Map<String, dynamic> json) {
    if (json['success'] != true || json['version'] is! num) {
      throw const FormatException('invalid PIN set response');
    }
    return SetPinResponse(version: (json['version'] as num).toInt());
  }
}

class ValidatePinResponse {
  const ValidatePinResponse({required this.valid});

  final bool valid;

  factory ValidatePinResponse.fromJson(Map<String, dynamic> json) {
    if (json['success'] != true || json['valid'] is! bool) {
      throw const FormatException('invalid PIN validation response');
    }
    return ValidatePinResponse(valid: json['valid'] as bool);
  }
}

/// Talks to the issuer backend.
class ApiService {
  ApiService({String? baseUrl, http.Client? client})
      : baseUrl = baseUrl ??
            const String.fromEnvironment(
              'API_BASE_URL',
              defaultValue: 'http://localhost:8080',
            ),
        _client = client ?? http.Client();

  final String baseUrl;
  final http.Client _client;

  /// Runs the app side of one operation and returns the envelope to submit.
  ///
  /// This is the per-operation sequence from the blog post:
  ///   1. Begin an operation for this PAN. The backend returns a single-use
  ///      operation ID and the Payment Cryptography agreement certificate.
  ///   2. Generate a fresh P-256 key pair and CSR.
  ///   3. Have the backend obtain an AWS Private CA certificate for the CSR,
  ///      bound to the operation.
  ///   4. ECDH + KDF + ISO-0 PIN block encryption, all in the app.
  Future<PinEnvelope> prepareEnvelope({
    required CryptoService crypto,
    required PinOperationType type,
    required String pan,
    required String pin,
  }) async {
    final operation = await _post('/api/operations', {
      'type': type.wireName,
      'pan': pan,
    });
    final operationId = _requireString(operation, 'operation_id');
    final agreementCertificate =
        _requireString(operation, 'agreement_certificate_pem');

    final ephemeral = crypto.generateEphemeralKeyAndCsr();

    final signed = await _post('/api/csr-sign', {
      'operation_id': operationId,
      'csr_pem': ephemeral.csrPem,
    });
    final clientCertificate = _requireString(signed, 'certificate_pem');

    final encrypted = crypto.encryptPin(
      appPrivateKey: ephemeral.privateKey,
      agreementCertificatePem: agreementCertificate,
      pin: pin,
      pan: pan,
      sharedInformation: crypto.newSharedInformation(),
    );

    return PinEnvelope(
      operationId: operationId,
      pan: pan,
      encryptedPinBlock: encrypted.encryptedPinBlockHex,
      clientCertificatePem: clientCertificate,
      sharedInformation: encrypted.sharedInformationHex,
    );
  }

  /// Step 5 (set): submit the envelope. The backend translates the PIN block
  /// and hands it to the processor, which enrolls the PIN.
  Future<SetPinResponse> setPin(PinEnvelope envelope) async {
    return SetPinResponse.fromJson(
      await _post(PinOperationType.set.submitPath, envelope.toJson()),
    );
  }

  /// Step 5 (validate): submit the envelope for a PIN attempt. The processor
  /// stand-in verifies it against the stored PVV.
  Future<ValidatePinResponse> validatePin(PinEnvelope envelope) async {
    return ValidatePinResponse.fromJson(
      await _post(PinOperationType.validate.submitPath, envelope.toJson()),
    );
  }

  Future<Map<String, dynamic>> _post(String path, Object body) async {
    final response = await _client.post(
      Uri.parse('$baseUrl$path'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    Object? decoded;
    try {
      decoded = jsonDecode(response.body);
    } on FormatException {
      throw Exception('$path failed');
    }
    if (response.statusCode < 200 ||
        response.statusCode >= 300 ||
        decoded is! Map<String, dynamic>) {
      throw Exception('$path failed');
    }
    return decoded;
  }

  String _requireString(Map<String, dynamic> json, String key) {
    final value = json[key];
    if (value is! String || value.isEmpty) {
      throw FormatException('missing $key');
    }
    return value;
  }
}
