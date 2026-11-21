import 'package:material_ui/material_ui.dart';

const _ink = Color(0xff344e41);
const _muted = Color(0xff6e7c6a);
const _green = Color(0xff3a5a40);

String alertStatus(String status) => switch (status) {
  'reviewed' => 'Marcada como revisada',
  'false_positive' => 'Marcada como posible falso positivo',
  _ => 'Pendiente de revisar',
};

String alertSeverity(int severity) => switch (severity) {
  1 => 'Alta',
  2 => 'Media',
  3 => 'Baja',
  _ => 'Nivel $severity',
};

String alertCategory(String signature) {
  final value = signature.toUpperCase();
  if (value.contains('NETSHIELD') && value.contains('TEST') && value.contains('SIMULATED')) return 'Prueba simulada';
  if (RegExp(r'\bPHISHING\b').hasMatch(value)) return 'Phishing';
  if (RegExp(r'\bTROJAN\b').hasMatch(value)) return 'Troyano';
  if (RegExp(r'\bMALWARE\b').hasMatch(value)) return 'Malware';
  if (RegExp(r'\bEXPLOIT\b').hasMatch(value)) return 'Explotación';
  if (RegExp(r'\bCNC\b').hasMatch(value)) return 'Comando y control';
  return 'No especificada';
}

String alertDate(String raw) {
  final date = DateTime.tryParse(raw);
  if (date == null) return raw;
  final local = date.toLocal();
  String two(int number) => number.toString().padLeft(2, '0');
  return '${two(local.day)}/${two(local.month)}/${local.year} · ${two(local.hour)}:${two(local.minute)}:${two(local.second)} (hora local)';
}

class AlertCard extends StatelessWidget {
  const AlertCard({super.key, required this.item, required this.busy, required this.onReview});
  final Map<String, dynamic> item;
  final bool busy;
  final void Function(int, String) onReview;

  @override
  Widget build(BuildContext context) {
    final signature = item['signature'] as String;
    final category = alertCategory(signature);
    final severity = item['severity'] as int;
    final status = item['review_status'] as String;
    final device = item['device_id'] as String;
    final timestamp = item['occurred_at'] as String;
    final reviewedAt = item['reviewed_at'];
    final severityColor = switch (severity) {
      1 => const Color(0xffb13f3a),
      2 => const Color(0xffa76b1c),
      3 => const Color(0xff477c65),
      _ => const Color(0xff65736c),
    };
    return Container(
      decoration: BoxDecoration(gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [severityColor.withValues(alpha: .10), Colors.white.withValues(alpha: .72)]), borderRadius: BorderRadius.circular(19), border: Border.all(color: severityColor.withValues(alpha: .38)), boxShadow: [BoxShadow(color: severityColor.withValues(alpha: .06), blurRadius: 15, offset: const Offset(0, 5))]),
      child: Theme(data: Theme.of(context).copyWith(dividerColor: Colors.transparent), child: ExpansionTile(
        key: PageStorageKey('alert-${item['id']}'),
        tilePadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 4),
        childrenPadding: const EdgeInsets.fromLTRB(18, 0, 18, 18),
        shape: const RoundedRectangleBorder(side: BorderSide.none),
        collapsedShape: const RoundedRectangleBorder(side: BorderSide.none),
        leading: Container(width: 38, height: 38, decoration: BoxDecoration(color: severityColor.withValues(alpha: .14), borderRadius: BorderRadius.circular(12)), child: Icon(category == 'Prueba simulada' ? Icons.science_outlined : Icons.shield_outlined, color: severityColor, size: 21)),
        title: Text(signature, style: const TextStyle(color: _ink, fontWeight: FontWeight.w800, fontSize: 14)),
        subtitle: Padding(padding: const EdgeInsets.only(top: 8), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Wrap(spacing: 8, runSpacing: 5, crossAxisAlignment: WrapCrossAlignment.center, children: [
            Text(category, style: const TextStyle(color: _green, fontWeight: FontWeight.w700, fontSize: 11)),
            Container(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4), decoration: BoxDecoration(color: severityColor.withValues(alpha: .13), borderRadius: BorderRadius.circular(20)), child: Text('Severidad ${alertSeverity(severity)}', style: TextStyle(color: severityColor, fontWeight: FontWeight.w800, fontSize: 11))),
          ]),
          const SizedBox(height: 5),
          Text('Dispositivo ${device.substring(0, 8)} · ${alertDate(timestamp)}', style: const TextStyle(color: _muted, fontSize: 12)),
          const SizedBox(height: 5),
          Text(alertStatus(status), style: const TextStyle(color: _green, fontSize: 12)),
        ])),
        children: [Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Divider(height: 18),
          const Text('Detalles de la detección', style: TextStyle(color: _ink, fontWeight: FontWeight.w800, fontSize: 13)),
          const SizedBox(height: 10),
          _Detail(label: 'Identificador', value: '#${item['id']}'),
          _Detail(label: 'Categoría indicada por la firma', value: category),
          _Detail(label: 'Severidad del sensor', value: '${alertSeverity(severity)} ($severity)'),
          _Detail(label: 'Fecha del evento', value: alertDate(timestamp)),
          _Detail(label: 'Dispositivo', value: device),
          if (reviewedAt is String) _Detail(label: 'Última revisión', value: alertDate(reviewedAt)),
          const SizedBox(height: 10),
          Text(category == 'Prueba simulada'
            ? 'Esta detección es una prueba y no indica una infección.'
            : 'La firma es un indicio, no una confirmación de infección. El sensor no conserva aquí el dominio, la URL ni el contenido de la conexión.',
            style: const TextStyle(color: _muted, fontSize: 12, height: 1.45)),
          const SizedBox(height: 10),
          const Text('Revisión', style: TextStyle(color: _ink, fontWeight: FontWeight.w800, fontSize: 13)),
          Wrap(spacing: 8, children: [
            TextButton(onPressed: busy || status == 'reviewed' ? null : () => onReview(item['id'] as int, 'reviewed'), child: const Text('Revisada')),
            TextButton(onPressed: busy || status == 'false_positive' ? null : () => onReview(item['id'] as int, 'false_positive'), child: const Text('Posible falso positivo')),
            if (status != 'new') TextButton(onPressed: busy ? null : () => onReview(item['id'] as int, 'new'), child: const Text('Pendiente')),
          ]),
        ])],
      )),
    );
  }
}

class _Detail extends StatelessWidget {
  const _Detail({required this.label, required this.value});
  final String label, value;
  @override
  Widget build(BuildContext context) => Padding(padding: const EdgeInsets.only(bottom: 7), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text(label, style: const TextStyle(color: _muted, fontSize: 11)),
    const SizedBox(height: 2),
    Text(value, style: const TextStyle(color: _ink, fontSize: 12, height: 1.35)),
  ]));
}
