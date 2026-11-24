import 'dart:io';
import 'package:material_ui/material_ui.dart';

/// Animated mini-map of the VPN server region (desktop only for now).
/// The server lives in Oracle Cloud's mx-queretaro-1 region (Queretaro,
/// Mexico, 20.5881, -100.3881), so the map is a stylized Mexico with a
/// pulsing marker on Queretaro. The pulse stays off under `flutter test`
/// so widget tests keep settling.

const _mapInk = Color(0xff344e41);
const _mapMuted = Color(0xff55655b);
const _mapGreen = Color(0xff3a5a40);
const _mapFill = Color(0xffa3b18a);

class VpnMapCard extends StatefulWidget {
  const VpnMapCard({super.key, required this.connected});
  final bool connected;
  @override
  State<VpnMapCard> createState() => _VpnMapCardState();
}

class _VpnMapCardState extends State<VpnMapCard> with SingleTickerProviderStateMixin {
  AnimationController? _rings;

  @override
  void initState() {
    super.initState();
    _syncRings();
  }

  @override
  void didUpdateWidget(covariant VpnMapCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.connected != widget.connected) _syncRings();
  }

  void _syncRings() {
    // Pulse only when connected, and never under `flutter test`.
    final shouldPulse = widget.connected && !Platform.environment.containsKey('FLUTTER_TEST');
    if (shouldPulse && _rings == null) {
      _rings = AnimationController(vsync: this, duration: const Duration(milliseconds: 2400))..repeat();
    } else if (!shouldPulse) {
      _rings?.dispose();
      _rings = null;
    }
  }

  @override
  void dispose() {
    _rings?.dispose();
    super.dispose();
  }

  Widget _mapContent(double ringProgress) => Container(
    decoration: const BoxDecoration(
      gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xffe9efe2), Color(0xffdbe5d2)]),
    ),
    child: CustomPaint(
      painter: const _MexicoPainter(),
      foregroundPainter: _MarkerPainter(connected: widget.connected, ringProgress: ringProgress),
    ),
  );

  @override
  Widget build(BuildContext context) {
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
          const Expanded(child: Text('Tu ubicación VPN', style: TextStyle(color: _mapInk, fontWeight: FontWeight.w800, fontSize: 15))),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
            decoration: BoxDecoration(color: (widget.connected ? _mapGreen : _mapMuted).withValues(alpha: .12), borderRadius: BorderRadius.circular(20)),
            child: Text(widget.connected ? 'En línea' : 'En espera', style: TextStyle(color: widget.connected ? _mapGreen : _mapMuted, fontWeight: FontWeight.w800, fontSize: 11)),
          ),
        ]),
        const SizedBox(height: 12),
        SizedBox(
          height: 170,
          width: double.infinity,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(14),
            child: rings == null
                ? _mapContent(0)
                : AnimatedBuilder(animation: rings, builder: (context, _) => _mapContent(rings.value)),
          ),
        ),
        const SizedBox(height: 12),
        const Text('Querétaro, México', style: TextStyle(color: _mapInk, fontWeight: FontWeight.w800, fontSize: 15)),
        const SizedBox(height: 3),
        Text(widget.connected ? 'Tu tráfico sale por el servidor de Oracle Cloud en Querétaro.' : 'Al conectar, tu tráfico saldrá por el servidor de Oracle Cloud en Querétaro.', style: const TextStyle(color: _mapMuted, fontSize: 13, height: 1.4)),
      ]),
    );
  }
}

/// Simplified Mexico outline (normalized 0..1 coords, y = 0 north).
/// Queretaro (20.5881, -100.3881) lands at about (0.54, 0.66).
class _MexicoPainter extends CustomPainter {
  const _MexicoPainter();

  static const _mainland = [
    Offset(0.02, 0.02), Offset(0.34, 0.04), Offset(0.52, 0.18),
    Offset(0.64, 0.37), Offset(0.62, 0.57), Offset(0.68, 0.74),
    Offset(0.73, 0.80), Offset(0.89, 0.63), Offset(0.98, 0.63),
    Offset(0.93, 0.82), Offset(0.80, 0.98), Offset(0.73, 0.92),
    Offset(0.55, 0.88), Offset(0.41, 0.76), Offset(0.38, 0.66),
    Offset(0.34, 0.52), Offset(0.23, 0.25),
  ];
  static const _baja = [
    Offset(0.01, 0.02), Offset(0.08, 0.18), Offset(0.16, 0.38),
    Offset(0.22, 0.52), Offset(0.15, 0.40), Offset(0.08, 0.20),
  ];

  Path _path(Size size, List<Offset> points) {
    final path = Path();
    for (var i = 0; i < points.length; i++) {
      final p = Offset(points[i].dx * size.width, points[i].dy * size.height);
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
    final dot = Paint()..color = const Color(0xff8da980).withValues(alpha: .35);
    for (var gx = 0.05; gx < 1; gx += 0.1) {
      for (var gy = 0.05; gy < 1; gy += 0.1) {
        canvas.drawCircle(Offset(gx * size.width, gy * size.height), 1.2, dot);
      }
    }
    final fill = Paint()..color = _mapFill.withValues(alpha: .75)..style = PaintingStyle.fill;
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

/// Marker on Queretaro, with two expanding rings while connected.
/// `ringProgress` 0..1 drives the rings; 0 means a static dot.
class _MarkerPainter extends CustomPainter {
  const _MarkerPainter({required this.connected, this.ringProgress = 0});
  final bool connected;
  final double ringProgress;

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(0.536 * size.width, 0.662 * size.height);
    if (connected) {
      for (final phase in [0.0, 0.5]) {
        final p = (ringProgress + phase) % 1.0;
        final radius = 8 + p * 26;
        final alpha = (1 - p) * .45;
        final ring = Paint()..color = _mapGreen.withValues(alpha: alpha)..style = PaintingStyle.stroke..strokeWidth = 2;
        canvas.drawCircle(center, radius, ring);
      }
      final dot = Paint()..color = _mapGreen;
      canvas.drawCircle(center, 7, dot);
      final halo = Paint()..color = Colors.white.withValues(alpha: .9);
      canvas.drawCircle(center, 3.2, halo);
    } else {
      final dot = Paint()..color = _mapMuted;
      canvas.drawCircle(center, 6, dot);
      final halo = Paint()..color = Colors.white.withValues(alpha: .9);
      canvas.drawCircle(center, 2.6, halo);
    }
  }

  @override
  bool shouldRepaint(covariant _MarkerPainter oldDelegate) =>
      connected != oldDelegate.connected || ringProgress != oldDelegate.ringProgress;
}
