import 'package:material_ui/material_ui.dart';
import '../services/api_client.dart';
import 'format_bytes.dart';

class _DayUsage {
  _DayUsage(this.day);
  final String day;
  int upload = 0, download = 0;
  bool incomplete = false, measured = false, uploadKnown = false, downloadKnown = false;
  void add(VpnUsageDay value) {
    if (value.uploadBytes != null) { upload += value.uploadBytes!; uploadKnown = true; measured = true; }
    if (value.downloadBytes != null) { download += value.downloadBytes!; downloadKnown = true; measured = true; }
    incomplete = incomplete || value.incomplete || value.uploadBytes == null || value.downloadBytes == null;
  }
}

/// Daily server samples, aggregated by UTC day across the user's devices.
class UsageChart extends StatelessWidget {
  const UsageChart({super.key, required this.history});
  final List<VpnUsageDay> history;

  @override
  Widget build(BuildContext context) {
    final byDay = <String, _DayUsage>{};
    for (final item in history) {
      byDay.putIfAbsent(item.day, () => _DayUsage(item.day)).add(item);
    }
    final days = byDay.values.toList()..sort((a, b) => a.day.compareTo(b.day));
    final shown = days.length > 7 ? days.sublist(days.length - 7) : days;
    if (shown.isEmpty || !shown.any((day) => day.measured)) {
      return const Text('Aún no hay intervalos medibles para la gráfica.', style: TextStyle(color: Color(0xff6e7c6a), fontSize: 12));
    }
    final maxBytes = shown.map((day) => day.upload + day.download).reduce((a, b) => a > b ? a : b);
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const Text('Consumo por día', style: TextStyle(color: Color(0xff344e41), fontSize: 16, fontWeight: FontWeight.w800)),
      const SizedBox(height: 5),
      const Text('Últimos 7 días con muestras · suma de dispositivos · UTC', style: TextStyle(color: Color(0xff6e7c6a), fontSize: 12)),
      const SizedBox(height: 14),
      Wrap(spacing: 16, runSpacing: 8, children: const [
        _Legend(color: Color(0xff588157), label: 'Recibido'),
        _Legend(color: Color(0xffa3b18a), label: 'Enviado'),
      ]),
      const SizedBox(height: 12),
      SizedBox(height: 160, child: Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
        for (final day in shown) Expanded(child: _DayBar(day: day, maximum: maxBytes)),
      ])),
      const SizedBox(height: 9),
      const Text('* Muestra incompleta. Los días sin muestras no se muestran; los valores son estimaciones.', style: TextStyle(color: Color(0xff6e7c6a), fontSize: 11, height: 1.4)),
    ]);
  }
}

class _Legend extends StatelessWidget {
  const _Legend({required this.color, required this.label});
  final Color color;
  final String label;
  @override
  Widget build(BuildContext context) => Row(mainAxisSize: MainAxisSize.min, children: [
    Container(width: 9, height: 9, decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(3))),
    const SizedBox(width: 6), Text(label, style: const TextStyle(color: Color(0xff6e7c6a), fontSize: 11)),
  ]);
}

class _DayBar extends StatelessWidget {
  const _DayBar({required this.day, required this.maximum});
  final _DayUsage day;
  final int maximum;
  @override
  Widget build(BuildContext context) {
    final total = day.upload + day.download;
    final height = maximum == 0 ? 0.0 : (total / maximum * 110).clamp(0.0, 110.0);
    final receivedHeight = total == 0 ? 0.0 : height * day.download / total;
    final sentHeight = height - receivedHeight;
    final received = day.downloadKnown ? formatBytes(day.download) : 'sin datos';
    final sent = day.uploadKnown ? formatBytes(day.upload) : 'sin datos';
    final description = '${day.day}, recibido $received, enviado $sent${day.incomplete ? ', muestra incompleta' : ''}';
    return Semantics(label: day.measured ? description : '${day.day}, sin intervalo medible', child:
      Tooltip(message: day.measured ? description : '${day.day}: sin intervalo medible', child: Column(mainAxisAlignment: MainAxisAlignment.end, children: [
        Text(day.measured ? formatBytes(total) : '—', maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Color(0xff6e7c6a), fontSize: 9)),
        const SizedBox(height: 5),
        if (height == 0) Container(width: 19, height: 3, decoration: BoxDecoration(color: const Color(0xffc9d2c1), borderRadius: BorderRadius.circular(4)))
        else ClipRRect(borderRadius: BorderRadius.circular(5), child: SizedBox(width: 20, height: height, child: Column(children: [
          SizedBox(height: sentHeight, child: const ColoredBox(color: Color(0xffa3b18a), child: SizedBox.expand())),
          SizedBox(height: receivedHeight, child: const ColoredBox(color: Color(0xff588157), child: SizedBox.expand())),
        ]))),
        const SizedBox(height: 7),
        Text('${day.day.substring(5)}${day.incomplete ? '*' : ''}', style: const TextStyle(color: Color(0xff6e7c6a), fontSize: 10)),
      ])));
  }
}
