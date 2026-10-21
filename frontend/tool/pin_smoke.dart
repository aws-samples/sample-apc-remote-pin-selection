// End-to-end smoke test against a running backend and real AWS resources.
//
//   API_BASE_URL=http://localhost:8080 dart run tool/pin_smoke.dart
//
// Sets a PIN for a synthetic PAN, validates the correct PIN, confirms a wrong
// PIN is rejected, and confirms a replayed envelope is refused. Override
// SMOKE_PAN and SMOKE_PIN if needed. Never use real cardholder data.
import 'dart:io';

import 'package:remote_pin_selection_demo/services/api_service.dart';
import 'package:remote_pin_selection_demo/services/crypto_service.dart';

Future<void> main() async {
  final env = Platform.environment;
  final api =
      ApiService(baseUrl: env['API_BASE_URL'] ?? 'http://127.0.0.1:8080');
  final crypto = CryptoService();
  final pan = env['SMOKE_PAN'] ?? '4000123456789010';
  final pin = env['SMOKE_PIN'] ?? '1379';
  final wrongPin = pin == '2468' ? '1379' : '2468';

  Future<PinEnvelope> envelope(PinOperationType type, String pin) =>
      api.prepareEnvelope(crypto: crypto, type: type, pan: pan, pin: pin);

  final setEnvelope = await envelope(PinOperationType.set, pin);
  final enrolled = await api.setPin(setEnvelope);

  final correct =
      await api.validatePin(await envelope(PinOperationType.validate, pin));
  final wrong = await api
      .validatePin(await envelope(PinOperationType.validate, wrongPin));

  var replayRejected = false;
  try {
    await api.setPin(setEnvelope);
  } on Exception {
    replayRejected = true;
  }

  if (!correct.valid || wrong.valid || !replayRejected) {
    stderr.writeln('Smoke test FAILED: correct=${correct.valid} '
        'wrong=${wrong.valid} replayRejected=$replayRejected');
    exitCode = 1;
    return;
  }
  stdout.writeln('Smoke test passed: PIN set (record version '
      '${enrolled.version}), correct PIN accepted, wrong PIN rejected, '
      'replayed envelope refused.');
}
