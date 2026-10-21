import 'package:flutter/material.dart';
import 'package:flutter_web_plugins/url_strategy.dart';

import 'services/api_service.dart';
import 'services/crypto_service.dart';
import 'widgets/user_pin_form.dart';

void main() {
  usePathUrlStrategy();
  runApp(const RemotePinApp());
}

/// Remote PIN selection demo app.
///
///   /              home
///   /pin/set       select (or reset) a PIN
///   /pin/validate  check a PIN against the processor stand-in
class RemotePinApp extends StatelessWidget {
  const RemotePinApp({super.key, this.api, this.initialRoute});

  final ApiService? api;
  final String? initialRoute;

  @override
  Widget build(BuildContext context) {
    final service = api ?? ApiService();
    return MaterialApp(
      title: 'Remote PIN Selection Demo',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      initialRoute: initialRoute,
      routes: {
        '/': (_) => const HomePage(),
        '/pin/set': (_) => SetPinPage(api: service),
        '/pin/validate': (_) => ValidatePinPage(api: service),
      },
      onUnknownRoute: (_) => MaterialPageRoute<void>(
        settings: const RouteSettings(name: '/'),
        builder: (_) => const HomePage(),
      ),
      debugShowCheckedModeBanner: false,
    );
  }
}

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Remote PIN Selection Demo')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: ListView(
            padding: const EdgeInsets.all(24),
            children: [
              Text(
                'Choose a PIN operation',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              const SizedBox(height: 8),
              const Text(
                'Use synthetic PANs and test PINs only. The PIN is encrypted '
                'in this app; the backend never receives it in the clear.',
              ),
              const SizedBox(height: 24),
              _WorkflowTile(
                icon: Icons.lock_reset,
                title: 'Set PIN',
                subtitle: 'Select or reset the PIN for a card.',
                onTap: () => Navigator.pushNamed(context, '/pin/set'),
              ),
              const SizedBox(height: 12),
              _WorkflowTile(
                icon: Icons.verified_user_outlined,
                title: 'Validate PIN',
                subtitle: 'Check a PIN against the processor stand-in.',
                onTap: () => Navigator.pushNamed(context, '/pin/validate'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _WorkflowTile extends StatelessWidget {
  const _WorkflowTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
        leading: Icon(icon, size: 30),
        title: Text(title),
        subtitle: Text(subtitle),
        trailing: const Icon(Icons.arrow_forward),
        onTap: onTap,
      ),
    );
  }
}

class SetPinPage extends StatefulWidget {
  const SetPinPage({super.key, required this.api});

  final ApiService api;

  @override
  State<SetPinPage> createState() => _SetPinPageState();
}

class _SetPinPageState extends State<SetPinPage> {
  final _crypto = CryptoService();
  String? _result;
  String? _enrolledPAN;
  bool _busy = false;

  Future<void> _submit(String pan, String pin) async {
    setState(() {
      _busy = true;
      _result = null;
      _enrolledPAN = null;
    });
    try {
      // Each submission is a new operation with fresh keys and a fresh
      // certificate; a failed operation is never retried.
      final envelope = await widget.api.prepareEnvelope(
        crypto: _crypto,
        type: PinOperationType.set,
        pan: pan,
        pin: pin,
      );
      final response = await widget.api.setPin(envelope);
      if (!mounted) return;
      setState(() {
        _enrolledPAN = pan;
        _result = 'PIN set. Verifier record version ${response.version}.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() => _result = 'The PIN could not be set. Try again.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return _WorkflowPage(
      title: 'Set PIN',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          UserPinForm(busy: _busy, submitLabel: 'Set PIN', onSubmit: _submit),
          if (_result != null) ...[
            const SizedBox(height: 16),
            _ResultBanner(message: _result!, success: _enrolledPAN != null),
          ],
          if (_enrolledPAN != null) ...[
            const SizedBox(height: 12),
            const _ProcessorNote(
              'Processor side (demo stand-in): the backend handed the '
              'translated PIN block to a stand-in processor, which generated '
              'a Visa PVV and stored it in DynamoDB. In production the banking '
              'system or card processor does this.',
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: () => Navigator.pushNamed(
                context,
                '/pin/validate',
                arguments: _enrolledPAN,
              ),
              icon: const Icon(Icons.verified_user_outlined),
              label: const Text('Validate this PIN'),
            ),
          ],
        ],
      ),
    );
  }
}

class ValidatePinPage extends StatefulWidget {
  const ValidatePinPage({super.key, required this.api});

  final ApiService api;

  @override
  State<ValidatePinPage> createState() => _ValidatePinPageState();
}

class _ValidatePinPageState extends State<ValidatePinPage> {
  final _crypto = CryptoService();
  String? _result;
  bool? _valid;
  bool _busy = false;
  String? _initialPAN;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // Prefilled when arriving from the Set PIN page.
    _initialPAN ??= ModalRoute.of(context)?.settings.arguments as String?;
  }

  Future<void> _submit(String pan, String pin) async {
    setState(() {
      _busy = true;
      _result = null;
      _valid = null;
    });
    try {
      final envelope = await widget.api.prepareEnvelope(
        crypto: _crypto,
        type: PinOperationType.validate,
        pan: pan,
        pin: pin,
      );
      final response = await widget.api.validatePin(envelope);
      if (!mounted) return;
      setState(() {
        _valid = response.valid;
        _result = response.valid ? 'PIN is valid.' : 'PIN is not valid.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() => _result = 'The PIN could not be checked. Try again.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return _WorkflowPage(
      title: 'Validate PIN',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const _ProcessorNote(
            'Processor side (demo stand-in): in production, PIN verification '
            'happens at the card processor when the card is used. This page '
            'exists only to show that the PIN you set works.',
          ),
          const SizedBox(height: 16),
          UserPinForm(
            initialPAN: _initialPAN,
            busy: _busy,
            submitLabel: 'Validate PIN',
            onSubmit: _submit,
          ),
          if (_result != null) ...[
            const SizedBox(height: 16),
            _ResultBanner(message: _result!, success: _valid == true),
          ],
        ],
      ),
    );
  }
}

class _WorkflowPage extends StatelessWidget {
  const _WorkflowPage({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(title),
        leading: IconButton(
          tooltip: 'Home',
          onPressed: () =>
              Navigator.pushNamedAndRemoveUntil(context, '/', (route) => false),
          icon: const Icon(Icons.home_outlined),
        ),
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: child,
          ),
        ),
      ),
    );
  }
}

class _ProcessorNote extends StatelessWidget {
  const _ProcessorNote(this.message);

  final String message;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: colors.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.info_outline),
          const SizedBox(width: 10),
          Expanded(child: Text(message)),
        ],
      ),
    );
  }
}

class _ResultBanner extends StatelessWidget {
  const _ResultBanner({required this.message, required this.success});

  final String message;
  final bool success;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: success ? colors.primaryContainer : colors.errorContainer,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        children: [
          Icon(success ? Icons.check_circle_outline : Icons.error_outline),
          const SizedBox(width: 10),
          Expanded(child: Text(message)),
        ],
      ),
    );
  }
}
