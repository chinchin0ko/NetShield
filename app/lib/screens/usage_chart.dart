import 'package:material_ui/material_ui.dart';
import '../services/api_client.dart';
import 'format_bytes.dart';

const _forest = Color(0xff344e41);
const _muted = Color(0xff6e7c6a);
const _received = Color(0xff588157);
const _sent = Color(0xffa3b18a);

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

/// Seven calendar days ending at the latest available UTC sample.
class UsageChart extends StatefulWidget {
  const UsageChart({super.key, required this.history});
  final List<VpnUsageDay> history;
  @override
  State<UsageChart> createState() => _UsageChartState();
}

class _UsageChartState extends State<UsageChart> {
  String? selectedDay;
  @override
  Widget build(BuildContext context) {
    final byDay = <String, _DayUsage>{};
    for (final item in widget.history) {
      if (DateTime.tryParse(item.day) == null) continue;
      byDay.putIfAbsent(item.day, () => _DayUsage(item.day)).add(item);
    }
    final dates = byDay.keys.toList()..sort();
    if (dates.isEmpty || !byDay.values.any((day) => day.measured)) {
      return const Text('Aún no hay intervalos medibles para la gráfica.', style: TextStyle(color: _muted, fontSize: 12));
    }
    final last = DateTime.parse('${dates.last}T00:00:00Z');
    final days = List.generate(7, (index) {
      final key = last.subtract(Duration(days: 6 - index)).toIso8601String().substring(0, 10);
      return byDay[key] ?? _DayUsage(key);
    });
    final measuredDays = days.where((day) => day.measured).toList();
    if (measuredDays.isEmpty) {
      return const Text('No hay intervalos medibles en los últimos siete días registrados.', style: TextStyle(color: _muted, fontSize: 12));
    }
    final selected = measuredDays.where((day) => day.day == selectedDay).firstOrNull ?? measuredDays.last;
    final maximum = days.map((day) => day.upload + day.download).reduce((a, b) => a > b ? a : b);
    final total = selected.upload + selected.download;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        Container(padding: const EdgeInsets.all(9), decoration: BoxDecoration(color: const Color(0xffe1ead9), borderRadius: BorderRadius.circular(12)), child: const Icon(Icons.insights_rounded, color: _received, size: 20)),
        const SizedBox(width: 11),
        const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Consumo por día', style: TextStyle(color: _forest, fontSize: 17, fontWeight: FontWeight.w800)),
          SizedBox(height: 3), Text('Tu actividad · UTC', style: TextStyle(color: _muted, fontSize: 11)),
        ])),
        Container(padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6), decoration: BoxDecoration(color: const Color(0xffe6ecdf), borderRadius: BorderRadius.circular(20)), child: const Text('7 DÍAS', style: TextStyle(color: _received, fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: .6))),
      ]),
      const SizedBox(height: 20),
      Text(formatBytes(total), key: const ValueKey('usage-selected-total'), style: const TextStyle(color: _forest, fontSize: 29, fontWeight: FontWeight.w900, letterSpacing: -.8)),
      const SizedBox(height: 3),
      Text('Total estimado · ${selected.day} UTC${selected.incomplete ? ' · incompleto' : ''}', style: const TextStyle(color: _muted, fontSize: 11)),
      const SizedBox(height: 17),
      Container(
        padding: const EdgeInsets.fromLTRB(7, 14, 7, 11),
        decoration: BoxDecoration(gradient: const LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xfff4f8f0), Color(0xffe7efe2)]), borderRadius: BorderRadius.circular(16), border: Border.all(color: Colors.white)),
        child: SizedBox(height: 155, child: Stack(children: [
          const Positioned.fill(child: CustomPaint(painter: _GridPainter())),
          Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
            for (final day in days) Expanded(child: _DayBar(day: day, maximum: maximum, selected: day.day == selected.day, onTap: day.measured ? () => setState(() => selectedDay = day.day) : null)),
          ]),
        ])),
      ),
      const SizedBox(height: 15),
      Wrap(spacing: 12, runSpacing: 8, children: [
        _Metric(color: _received, label: 'Recibido', value: selected.downloadKnown ? formatBytes(selected.download) : 'Sin datos'),
        _Metric(color: _sent, label: 'Enviado', value: selected.uploadKnown ? formatBytes(selected.upload) : 'Sin datos'),
      ]),
      const SizedBox(height: 12),
      const Text('Selecciona un día. — indica que no hay datos; * marca una muestra incompleta. Los valores son estimaciones.', style: TextStyle(color: _muted, fontSize: 11, height: 1.45)),
    ]);
  }
}

class _GridPainter extends CustomPainter {
  const _GridPainter();
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = const Color(0xffcddac8)..strokeWidth = 1;
    for (final fraction in [0.18, 0.46, 0.74]) {
      final y = size.height * fraction;
      for (double x = 0; x < size.width; x += 7) {
        canvas.drawLine(Offset(x, y), Offset((x + 3).clamp(0, size.width), y), paint);
      }
    }
  }
  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class _Metric extends StatelessWidget {
  const _Metric({required this.color, required this.label, required this.value});
  final Color color;
  final String label, value;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
    decoration: BoxDecoration(color: color.withValues(alpha: .09), borderRadius: BorderRadius.circular(11)),
    child: Row(mainAxisSize: MainAxisSize.min, children: [
      Container(width: 9, height: 9, decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(3))),
      const SizedBox(width: 7), Text('$label  ', style: const TextStyle(color: _muted, fontSize: 11)),
      Text(value, style: const TextStyle(color: _forest, fontWeight: FontWeight.w800, fontSize: 11)),
    ]),
  );
}

class _DayBar extends StatelessWidget {
  const _DayBar({required this.day, required this.maximum, required this.selected, required this.onTap});
  final _DayUsage day;
  final int maximum;
  final bool selected;
  final VoidCallback? onTap;
  @override
  Widget build(BuildContext context) {
    final total = day.upload + day.download;
    final height = maximum == 0 ? 0.0 : (total / maximum * 105).clamp(0.0, 105.0);
    final receivedHeight = total == 0 ? 0.0 : height * day.download / total;
    final sentHeight = height - receivedHeight;
    final received = day.downloadKnown ? formatBytes(day.download) : 'sin datos';
    final sent = day.uploadKnown ? formatBytes(day.upload) : 'sin datos';
    final description = '${day.day}, recibido $received, enviado $sent${day.incomplete ? ', muestra incompleta' : ''}';
    return Semantics(label: day.measured ? description : '${day.day}, sin intervalo medible', button: day.measured, selected: selected, child:
      Tooltip(message: day.measured ? description : '${day.day}: sin intervalo medible', child: InkWell(
        key: ValueKey('usage-day-${day.day}'), onTap: onTap, borderRadius: BorderRadius.circular(12),
        child: Column(mainAxisAlignment: MainAxisAlignment.end, children: [
          if (!day.measured) const Text('—', style: TextStyle(color: _muted, fontSize: 12))
          else if (height == 0) Container(width: 25, height: 3, decoration: BoxDecoration(color: _received, borderRadius: BorderRadius.circular(4)))
          else AnimatedContainer(duration: const Duration(milliseconds: 250), width: selected ? 29 : 23, height: height,
            decoration: BoxDecoration(borderRadius: BorderRadius.circular(7), boxShadow: selected ? [BoxShadow(color: _received.withValues(alpha: .28), blurRadius: 12, offset: const Offset(0, 4))] : []),
            child: ClipRRect(borderRadius: BorderRadius.circular(7), child: Column(children: [
              SizedBox(height: sentHeight, child: const ColoredBox(color: _sent, child: SizedBox.expand())),
              SizedBox(height: receivedHeight, child: const DecoratedBox(decoration: BoxDecoration(gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xff81a77b), _received])), child: SizedBox.expand())),
            ]))),
          const SizedBox(height: 8),
          Text('${day.day.substring(5)}${day.incomplete ? '*' : ''}', maxLines: 1, style: TextStyle(color: selected ? _forest : _muted, fontWeight: selected ? FontWeight.w800 : FontWeight.w400, fontSize: 9)),
        ]),
      )));
  }
}
