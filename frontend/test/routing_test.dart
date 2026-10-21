import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:remote_pin_selection_demo/main.dart';
import 'package:remote_pin_selection_demo/services/api_service.dart';
import 'package:remote_pin_selection_demo/services/crypto_service.dart';

class FakeApiService extends ApiService {
  PinOperationType? lastType;

  @override
  Future<PinEnvelope> prepareEnvelope({
    required CryptoService crypto,
    required PinOperationType type,
    required String pan,
    required String pin,
  }) async {
    lastType = type;
    return PinEnvelope(
      operationId: '0123456789abcdef0123456789abcdef',
      pan: pan,
      encryptedPinBlock: '0011223344556677',
      clientCertificatePem: 'client-certificate',
      sharedInformation: 'AB' * 32,
    );
  }

  @override
  Future<SetPinResponse> setPin(PinEnvelope envelope) async =>
      const SetPinResponse(version: 1);

  @override
  Future<ValidatePinResponse> validatePin(PinEnvelope envelope) async =>
      const ValidatePinResponse(valid: true);
}

void main() {
  testWidgets('home links navigate to both workflow pages', (tester) async {
    await tester.pumpWidget(RemotePinApp(api: FakeApiService()));

    await tester.tap(find.text('Set PIN').last);
    await tester.pumpAndSettle();
    expect(find.byType(SetPinPage), findsOneWidget);

    await tester.tap(find.byTooltip('Home'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Validate PIN').last);
    await tester.pumpAndSettle();
    expect(find.byType(ValidatePinPage), findsOneWidget);
  });

  testWidgets('set PIN shows the processor-side note after success',
      (tester) async {
    final api = FakeApiService();
    await tester.pumpWidget(RemotePinApp(api: api, initialRoute: '/pin/set'));
    await tester.pumpAndSettle();

    await tester.enterText(
        find.byKey(const Key('pan-field')), '4000123456789010');
    await tester.enterText(find.byKey(const Key('pin-field')), '1234');
    await tester.tap(find.widgetWithText(FilledButton, 'Set PIN'));
    await tester.pumpAndSettle();

    expect(api.lastType, PinOperationType.set);
    expect(find.textContaining('Verifier record version 1'), findsOneWidget);
    expect(find.textContaining('Processor side'), findsOneWidget);
  });

  testWidgets('validate PIN clears the PIN field and shows the result',
      (tester) async {
    final api = FakeApiService();
    await tester
        .pumpWidget(RemotePinApp(api: api, initialRoute: '/pin/validate'));
    await tester.pumpAndSettle();

    await tester.enterText(
        find.byKey(const Key('pan-field')), '4000123456789010');
    await tester.enterText(find.byKey(const Key('pin-field')), '1234');
    await tester.tap(find.widgetWithText(FilledButton, 'Validate PIN'));
    await tester.pumpAndSettle();

    final pinField =
        tester.widget<TextFormField>(find.byKey(const Key('pin-field')));
    expect(pinField.controller?.text, isEmpty);
    expect(api.lastType, PinOperationType.validate);
    expect(find.text('PIN is valid.'), findsOneWidget);
  });

  testWidgets('PAN and PIN fields accept only digits, up to their limits',
      (tester) async {
    await tester.pumpWidget(
        RemotePinApp(api: FakeApiService(), initialRoute: '/pin/set'));
    await tester.pumpAndSettle();

    await tester.enterText(
        find.byKey(const Key('pan-field')), '4000-1234 5678 9010 12345');
    await tester.enterText(find.byKey(const Key('pin-field')), '12a3456789');

    final panField =
        tester.widget<TextFormField>(find.byKey(const Key('pan-field')));
    final pinField =
        tester.widget<TextFormField>(find.byKey(const Key('pin-field')));
    expect(panField.controller?.text, '4000123456789010123');
    expect(pinField.controller?.text, '123456');
  });
}
