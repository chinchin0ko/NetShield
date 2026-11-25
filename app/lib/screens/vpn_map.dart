import 'dart:io';
import 'dart:math' as math;
import 'package:material_ui/material_ui.dart';

/// Server location, with connection health and a tunnel-bound IP supplied by
/// the connection controller. This widget never queries the physical network.
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
  const VpnMapCard({super.key, required this.connected, this.tunnelActive = false, this.publicIp});
  final bool connected;
  final bool tunnelActive;
  final String? publicIp;
  @override
  State<VpnMapCard> createState() => _VpnMapCardState();
}

class _VpnMapCardState extends State<VpnMapCard> with TickerProviderStateMixin {
  AnimationController? _fly;
  AnimationController? _rings;

  @override
  void initState() {
    super.initState();
    _syncAnimations();
  }

  @override
  void didUpdateWidget(covariant VpnMapCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.connected != widget.connected) {
      _syncAnimations();
      }
  }

  void _syncAnimations() {
    // Animate only outside `flutter test`.
    final animate = !Platform.environment.containsKey('FLUTTER_TEST');
    if (animate && _fly == null) {
      _fly = AnimationController(vsync: this, duration: const Duration(milliseconds: 1600));
      _rings = AnimationController(vsync: this, duration: const Duration(milliseconds: 2400))..repeat();
      // Start at the right end for the current state (no fly on first build).
      if (widget.connected) _fly!.value = 1;
    } else if (!animate) {
      _fly?.dispose();
      _rings?.dispose();
      _fly = null;
      _rings = null;
    }
    if (widget.connected) {
      _fly?.forward();
    } else {
      _fly?.reverse();
    }
  }

  Widget _mapContent(double flyProgress, double ringProgress) => Container(
    decoration: const BoxDecoration(
      gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xffe9efe2), Color(0xffdbe5d2)]),
    ),
    child: CustomPaint(
      painter: const _MexicoPainter(),
      foregroundPainter: _FlowPainter(connected: widget.connected, flyProgress: flyProgress, ringProgress: ringProgress),
    ),
  );

  @override
  void dispose() {
    _fly?.dispose();
    _rings?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final fly = _fly;
    final rings = _rings;
    // Under test, or before the first frame, snap to the current state.
    final flyProgress = fly?.value ?? (widget.connected ? 1.0 : 0.0);
    final ringProgress = rings?.value ?? 0.0;
    final ip = widget.connected ? widget.publicIp : null;
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
          Expanded(child: Text('Servidor VPN', style: const TextStyle(color: _mapInk, fontWeight: FontWeight.w800, fontSize: 15))),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
            decoration: BoxDecoration(color: (widget.connected ? _mapGreen : _mapMuted).withValues(alpha: .12), borderRadius: BorderRadius.circular(20)),
            child: Text(widget.connected ? 'Túnel verificado' : (widget.tunnelActive ? 'Sin verificar' : 'En espera'), style: TextStyle(color: widget.connected ? _mapGreen : _mapMuted, fontWeight: FontWeight.w800, fontSize: 11)),
          ),
        ]),
        const SizedBox(height: 12),
        SizedBox(
          height: 210,
          width: double.infinity,
          child: ClipRRect(
            borderRadius: BorderRadius.circular(14),
            child: fly == null
                ? _mapContent(flyProgress, ringProgress)
                : AnimatedBuilder(
                    animation: Listenable.merge([fly, rings!]),
                    builder: (context, _) => _mapContent(fly.value, rings.value),
                  ),
          ),
        ),
        const SizedBox(height: 12),
        Text(
          'Querétaro, México',
          style: const TextStyle(color: _mapInk, fontWeight: FontWeight.w800, fontSize: 15),
        ),
        const SizedBox(height: 3),
        Text(
          widget.connected
              ? (ip == null ? 'Túnel verificado. IP de salida todavía no verificada.' : 'IP de salida verificada: $ip · Servidor en Querétaro.')
              : 'Ubicación del servidor. No hay una salida VPN verificada.',
          style: const TextStyle(color: _mapMuted, fontSize: 13, height: 1.4),
        ),
      ]),
    );
  }
}

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

/// One marker at a time. `flyProgress` 0 = at your real location,
/// 1 = at the server. While it flies (0..1) the dot travels the arc and
/// the trail draws behind it; the origin fades out and the server fades in.
class _FlowPainter extends CustomPainter {
  const _FlowPainter({required this.connected, this.flyProgress = 0, this.ringProgress = 0});
  final bool connected;
  final double flyProgress;
  final double ringProgress;

  void _label(Canvas canvas, String text, Offset anchor) {
    final painter = TextPainter(
      text: TextSpan(text: text, style: const TextStyle(color: _mapInk, fontWeight: FontWeight.w800, fontSize: 12)),
      textDirection: TextDirection.ltr,
    )..layout();
    painter.paint(canvas, anchor);
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
    final p = flyProgress.clamp(0.0, 1.0);

    // Trail + travelling dot while the location is changing.
    if (p > 0.02 && p < 0.98) {
      final metric = route.computeMetrics().first;
      final total = metric.length;
      final line = Paint()..color = _mapGreen.withValues(alpha: .55)..style = PaintingStyle.stroke..strokeWidth = 2..strokeCap = StrokeCap.round;
      canvas.drawPath(metric.extractPath(0, p * total), line);
      final tip = metric.getTangentForOffset(p * total);
      if (tip != null) {
        final glow = Paint()..color = _mapAccent.withValues(alpha: .35);
        canvas.drawCircle(tip.position, 8, glow);
        final dot = Paint()..color = _mapAccent;
        canvas.drawCircle(tip.position, 4.5, dot);
      }
    }

    // Your real location: visible when disconnected, fades as you fly away.
    final originAlpha = (1 - p).clamp(0.0, 1.0);
    if (originAlpha > 0.02) {
      final dot = Paint()..color = _mapAccent.withValues(alpha: originAlpha);
      canvas.drawCircle(origin, 6.5, dot);
      final halo = Paint()..color = Colors.white.withValues(alpha: .9 * originAlpha);
      canvas.drawCircle(origin, 2.8, halo);
      _label(canvas, 'Tú', Offset(origin.dx + 10, origin.dy - 18));
    }

    // The server: fades in as you arrive, then pulses while connected.
    final destAlpha = p.clamp(0.0, 1.0);
    if (destAlpha > 0.02) {
      if (connected && p > 0.95) {
        for (final phase in [0.0, 0.5]) {
          final rp = (ringProgress + phase) % 1.0;
          final ring = Paint()..color = _mapGreen.withValues(alpha: (1 - rp) * .45)..style = PaintingStyle.stroke..strokeWidth = 2;
          canvas.drawCircle(dest, 8 + rp * 26, ring);
        }
      }
      final dot = Paint()..color = _mapGreen.withValues(alpha: destAlpha);
      canvas.drawCircle(dest, 7, dot);
      final halo = Paint()..color = Colors.white.withValues(alpha: .9 * destAlpha);
      canvas.drawCircle(dest, 3.2, halo);
      _label(canvas, 'Querétaro', Offset(dest.dx + 11, dest.dy - 6));
    }
  }

  @override
  bool shouldRepaint(covariant _FlowPainter oldDelegate) =>
      connected != oldDelegate.connected || flyProgress != oldDelegate.flyProgress || ringProgress != oldDelegate.ringProgress;
}
