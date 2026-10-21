import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// PAN and PIN entry. The PIN field is cleared after every submission so the
/// clear PIN does not linger in the widget tree.

class UserPinForm extends StatefulWidget {
  const UserPinForm({
    super.key,
    required this.busy,
    required this.submitLabel,
    required this.onSubmit,
    this.initialPAN,
  });

  final bool busy;
  final String submitLabel;
  final String? initialPAN;
  final Future<void> Function(String pan, String pin) onSubmit;

  @override
  State<UserPinForm> createState() => _UserPinFormState();
}

class _UserPinFormState extends State<UserPinForm> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _panController;
  final _pinController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _panController = TextEditingController(text: widget.initialPAN);
  }

  @override
  void dispose() {
    _panController.dispose();
    _pinController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    try {
      await widget.onSubmit(_panController.text, _pinController.text);
    } finally {
      _pinController.clear();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Form(
      key: _formKey,
      child: Column(
        children: [
          TextFormField(
            key: const Key('pan-field'),
            controller: _panController,
            enabled: !widget.busy,
            maxLength: 19,
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly],
            decoration: const InputDecoration(
              labelText: 'Synthetic PAN',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.credit_card),
            ),
            validator: (value) {
              if (value == null || !RegExp(r'^\d{13,19}$').hasMatch(value)) {
                return 'Enter a 13-19 digit synthetic PAN';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),
          TextFormField(
            key: const Key('pin-field'),
            controller: _pinController,
            enabled: !widget.busy,
            obscureText: true,
            maxLength: 6,
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly],
            decoration: const InputDecoration(
              labelText: 'PIN (4-6 digits)',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.lock_outline),
            ),
            validator: (value) {
              if (value == null || !RegExp(r'^\d{4,6}$').hasMatch(value)) {
                return 'Enter a 4-6 digit PIN';
              }
              return null;
            },
          ),
          const SizedBox(height: 8),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: widget.busy ? null : _submit,
              icon: widget.busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.send),
              label: Text(widget.busy ? 'Working...' : widget.submitLabel),
            ),
          ),
        ],
      ),
    );
  }
}
