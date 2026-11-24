import 'dart:io';
import 'dart:math' as math;
import 'package:material_ui/material_ui.dart';

/// Animated mini-map of the VPN connection flow (desktop only for now).
/// The server lives in Oracle Cloud's mx-queretaro-1 region (Queretaro,
/// Mexico, 20.5881, -100.3881). The map shows the flow in two steps:
/// first your location (Tuxtla Gutierrez, Chiapas, where Juan studies),
/// then the animated route to the Queretaro server. The Mexico outline
/// keeps its real 31:18 geographic aspect ratio so it never stretches.
/// The animations stay off under `flutter test` so widget tests settle.

const _mapInk = Color(0xff344e41);
const _mapMuted = Color(0xff55655b);
const _mapGreen = Color(0xff3a5a40);
const _mapFill = Color(0xffa3b18a);
const _mapAccent = Color(0xff2f6b3a);

/// lon/lat -> normalized coords. Mexico spans lon -117..-86, lat 14.5..32.5.
Offset _ll(double lon, double lat) => Offset((lon + 117) / 31, (32.5 - lat) / 18);

/// Normalized coords -> canvas coords, preserving the 31:18 aspect ratio
/// and centering the shape in the available space.
Offset _place(Size size, Offset n) {
  final scale = math.min(size.width / 31, size.height / 18);
  final dx = (size.width - 31 * scale) / 2;
  final dy = (size.height - 18 * scale) / 2;
  return Offset(dx + n.dx * 31 * scale, dy + n.dy * 18 * scale);
}

final _origin = _ll(-93.1, 16.75); // Tuxtla Gutierrez, Chiapas (you)
final _dest = _ll(-100.3881, 20.5881); // Queretaro server

class VpnMapCard extends StatefulWidget {
  const VpnMapCard({super.key, required this.connected});
  final bool connected;
  @override
  State<VpnMapCard> createState() => _VpnMapCardState();
}

class _VpnMapCardState extends State<VpnMapCard> with SingleTickerProviderStateMixin {
  AnimationController? _flow;
  AnimationController? _rings;

  @override
  void initState() {
    super.initState();
    _syncAnimations();
  }

  @override
  void didUpdateWidget(covariant VpnMapCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.connected != widget.connected) _syncAnimations();
  }

  void _syncAnimations() {
    // Animate only when connected, and never under `flutter test`.
    final animate = widget.connected && !Platform.environment.containsKey('FLUTTER_TEST');
    if (animate && _flow == null) {
      _flow = AnimationController(vsync: this, duration: const Duration(milliseconds: 3200))..repeat();
      _rings = AnimationController(vsync: this, duration: const Duration(milliseconds: 2400))..repeat();
    } else if (!animate) {
      _flow?.dispose();
      _rings?.dispose();
      _flow = null;
      _rings = null;
    }
  }

  @override
  void dispose() {
    _flow?.dispose();
    _rings?.dispose();
    super.dispose();
  }

  Widget _mapContent(double flowProgress, double ringProgress) => Container(
    decoration: const BoxDecoration(
      gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xffe9efe2), Color(0xffdbe5d2)]),
    ),
    child: CustomPaint(
      painter: const _MexicoPainter(),
      foregroundPainter: _FlowPainter(connected: widget.connected, flowProgress: flowProgress, ringProgress: ringProgress),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final flow = _flow;
    final rings = _rings;
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: .56),
        borderRadius: BorderRadius.circular(19),
        border: Border.all(color: Colors.white.withValues(alpha: .9)),
        boxShadow: [BoxShadow(color: _mapGreen.withValues(alpha: .05), blurRadius: 18, offset: const Offset(0, 7))],
      ),
      padding: const EdgeInsets.fromLTRB(18, 16, 18, 16),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          const Icon(Icons.map_outlined, color: _mapGreen, size: 20),
          const SizedBox(width: 10),
          const Expanded(child: Text('Tu ruta VPN', style: TextStyle(color: _mapInk, fontWeight: FontWeight.w800, fontSize: 15))),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
            decoration: BoxDecoration(color: (widget.connected ? _mapGreen : _mapMuted).withValues(alpha: .12), borderRadius: BorderRadius.circular(20)),
            child: Text(widget.connected ? 'En línea' : 'En espera', style: TextStyle(color: widget.connected ? _mapGreen : _mapMuted, fontWeight: FontWeight.w800, fontSize: 11)),
          ),
        ]),
        const SizedBox(height: 12),
        SizedBox(
          height: 210,
          width: double.infinity,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(14),
            child: flow == null
                ? _mapContent(0, 0)
                : AnimatedBuilder(
                    animation: Listenable.merge([flow, rings!]),
                    builder: (context, _) => _mapContent(flow.value, rings.value),
                  ),
          ),
        ),
        const SizedBox(height: 12),
        Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [_legendDot(_mapAccent), const SizedBox(width: 7), const Flexible(child: Text('Tú · Chiapas', style: TextStyle(color: _mapInk, fontWeight: FontWeight.w700, fontSize: 13)))]),
          const SizedBox(height: 6),
          Row(children: [_legendDot(_mapGreen), const SizedBox(width: 7), const Flexible(child: Text('Servidor · Querétaro', style: TextStyle(color: _mapInk, fontWeight: FontWeight.w700, fontSize: 13)))]),
        ]),
        const SizedBox(height: 4),
        Text(widget.connected ? 'Tu tráfico viaja de Chiapas al servidor de Oracle Cloud en Querétaro.' : 'Al conectar, tu tráfico viajará de Chiapas al servidor de Oracle Cloud en Querétaro.', style: const TextStyle(color: _mapMuted, fontSize: 13, height: 1.4)),
      ]),
    );
  }
}

Widget _legendDot(Color color) => Container(width: 10, height: 10, decoration: BoxDecoration(color: color, shape: BoxShape.circle, border: Border.all(color: Colors.white, width: 2), boxShadow: [BoxShadow(color: color.withValues(alpha: .35), blurRadius: 4, offset: const Offset(0, 1))]));

/// Simplified Mexico outline (lon/lat points), drawn with its real aspect.
class _MexicoPainter extends CustomPainter {
  const _MexicoPainter();

  static const _mainland = [
    (-117.0, 32.5), (-106.4, 31.8), (-102.9, 29.3), (-99.5, 26.9),
    (-97.2, 25.9), (-97.8, 22.2), (-96.1, 19.2), (-94.4, 18.1),
    (-90.5, 21.3), (-86.8, 21.2), (-88.3, 17.8), (-92.3, 14.9),
    (-94.5, 16.0), (-99.9, 16.8), (-104.3, 19.0), (-106.4, 23.2),
    (-109.5, 26.5), (-114.8, 31.8),
  ];
  static const _baja = [
    (-117.0, 32.5), (-116.0, 31.0), (-114.0, 28.0), (-112.0, 25.0),
    (-109.9, 22.9), (-111.0, 24.0), (-113.5, 27.5), (-116.5, 31.5),
  ];

  Path _path(Size size, List<(double, double)> points) {
    final path = Path();
    for (var i = 0; i < points.length; i++) {
      final p = _place(size, _ll(points[i].$1, points[i].$2));
      if (i == 0) {
        path.moveTo(p.dx, p.dy);
      } else {
        path.lineTo(p.dx, p.dy);
      }
    }
    path.close();
    return path;
  }

  @override
  void paint(Canvas canvas, Size size) {
    final dot = Paint()..color = const Color(0xff8da980).withValues(alpha: .3);
    for (var gx = 0.05; gx < 1; gx += 0.08) {
      for (var gy = 0.05; gy < 1; gy += 0.08) {
        canvas.drawCircle(Offset(gx * size.width, gy * size.height), 1.1, dot);
      }
    }
    final fill = Paint()..color = _mapFill.withValues(alpha: .8)..style = PaintingStyle.fill;
    final border = Paint()..color = _mapGreen.withValues(alpha: .55)..style = PaintingStyle.stroke..strokeWidth = 1.6..strokeJoin = StrokeJoin.round;
    for (final shape in [_mainland, _baja]) {
      final path = _path(size, shape);
      canvas.drawPath(path, fill);
      canvas.drawPath(path, border);
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

/// The connection flow: origin marker, animated route to the server,
/// pulsing destination rings, and labels. When disconnected the route is
/// a faint static line and both markers are still.
class _FlowPainter extends CustomPainter {
  const _FlowPainter({required this.connected, this.flowProgress = 0, this.ringProgress = 0});
  final bool connected;
  final double flowProgress;
  final double ringProgress;

  void _label(Canvas canvas, String text, Offset anchor, {bool alignRight = false}) {
    final painter = TextPainter(
      text: TextSpan(text: text, style: const TextStyle(color: _mapInk, fontWeight: FontWeight.w800, fontSize: 12)),
      textDirection: TextDirection.ltr,
    )..layout();
    final pos = alignRight ? Offset(anchor.dx - painter.width, anchor.dy) : anchor;
    painter.paint(canvas, pos);
  }

  @override
  void paint(Canvas canvas, Size size) {
    final origin = _place(size, _origin);
    final dest = _place(size, _dest);
    // Gentle arc from you to the server, bowed toward the north.
    final control = Offset((origin.dx + dest.dx) / 2 + 8, (origin.dy + dest.dy) / 2 - size.height * 0.16);
    final route = Path()
      ..moveTo(origin.dx, origin.dy)
      ..quadraticBezierTo(control.dx, control.dy, dest.dx, dest.dy);

    final line = Paint()..color = _mapGreen.withValues(alpha: connected ? .55 : .25)..style = PaintingStyle.stroke..strokeWidth = 2..strokeCap = StrokeCap.round;
    if (connected && flowProgress > 0.02) {
      final metric = route.computeMetrics().first;
      final total = metric.length;
      final drawn = metric.extractPath(0, flowProgress * total);
      canvas.drawPath(drawn, line);
      final tip = metric.getTangentForOffset(flowProgress * total);
      if (tip != null) {
        final glow = Paint()..color = _mapAccent.withValues(alpha: .35);
        canvas.drawCircle(tip.position, 7, glow);
        final dot = Paint()..color = _mapAccent;
        canvas.drawCircle(tip.position, 4, dot);
      }
    } else {
      canvas.drawPath(route, line);
    }

    // Origin marker: you.
    final originDot = Paint()..color = _mapAccent;
    canvas.drawCircle(origin, 6.5, originDot);
    final originHalo = Paint()..color = Colors.white.withValues(alpha: .9);
    canvas.drawCircle(origin, 2.8, originHalo);
    _label(canvas, 'Tú', Offset(origin.dx + 10, origin.dy - 18));

    // Destination marker: the server, pulsing while connected.
    if (connected) {
      for (final phase in [0.0, 0.5]) {
        final p = (ringProgress + phase) % 1.0;
        final ring = Paint()..color = _mapGreen.withValues(alpha: (1 - p) * .45)..style = PaintingStyle.stroke..strokeWidth = 2;
        canvas.drawCircle(dest, 8 + p * 26, ring);
      }
    }
    final destDot = Paint()..color = _mapGreen;
    canvas.drawCircle(dest, 7, destDot);
    final destHalo = Paint()..color = Colors.white.withValues(alpha: .9);
    canvas.drawCircle(dest, 3.2, destHalo);
    _label(canvas, 'Querétaro', Offset(dest.dx + 11, dest.dy - 6));
  }

  @override
  bool shouldRepaint(covariant _FlowPainter oldDelegate) =>
      connected != oldDelegate.connected || flowProgress != oldDelegate.flowProgress || ringProgress != oldDelegate.ringProgress;
}
