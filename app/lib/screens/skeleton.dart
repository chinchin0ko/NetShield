import 'package:material_ui/material_ui.dart';

/// Gray placeholder shapes shown while API content loads (skeleton loading).
/// Static gray on purpose: no repeating animation, so widget tests that use
/// pumpAndSettle stay safe while a skeleton is on screen.

class SkeletonBox extends StatelessWidget {
  const SkeletonBox({super.key, this.width, this.height = 14, this.radius = 7});
  final double? width;
  final double height;
  final double radius;
  @override
  Widget build(BuildContext context) => Container(
    width: width,
    height: height,
    decoration: BoxDecoration(
      color: const Color(0xffd9ddd6),
      borderRadius: BorderRadius.circular(radius),
    ),
  );
}

Widget _skeletonCard({required Widget child}) => Container(
  width: double.infinity,
  padding: const EdgeInsets.all(18),
  decoration: BoxDecoration(
    color: Colors.white.withValues(alpha: .56),
    borderRadius: BorderRadius.circular(19),
    border: Border.all(color: Colors.white.withValues(alpha: .9)),
    boxShadow: [BoxShadow(color: const Color(0xff3a5a40).withValues(alpha: .05), blurRadius: 18, offset: const Offset(0, 7))],
  ),
  child: child,
);

/// Mimics the two RECIBIDO / ENVIADO usage cards.
class SkeletonUsageCards extends StatelessWidget {
  const SkeletonUsageCards({super.key});
  @override
  Widget build(BuildContext context) => const Row(children: [
    Expanded(child: _SkeletonUsageCard()),
    SizedBox(width: 12),
    Expanded(child: _SkeletonUsageCard()),
  ]);
}

class _SkeletonUsageCard extends StatelessWidget {
  const _SkeletonUsageCard();
  @override
  Widget build(BuildContext context) => _skeletonCard(child: const Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    SkeletonBox(width: 20, height: 20, radius: 6),
    SizedBox(height: 15),
    SkeletonBox(width: 90, height: 21, radius: 7),
    SizedBox(height: 6),
    SkeletonBox(width: 70, height: 10, radius: 5),
  ]));
}

/// Mimics one device / history row (a card with a title and a subtitle line).
class SkeletonListRow extends StatelessWidget {
  const SkeletonListRow({super.key});
  @override
  Widget build(BuildContext context) => _skeletonCard(child: const Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    SkeletonBox(width: 180, height: 13, radius: 6),
    SizedBox(height: 7),
    SkeletonBox(width: 240, height: 12, radius: 6),
  ]));
}

/// Mimics one alert card (icon square + title + chip + two lines).
class SkeletonAlertCard extends StatelessWidget {
  const SkeletonAlertCard({super.key});
  @override
  Widget build(BuildContext context) => _skeletonCard(child: const Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
    SkeletonBox(width: 38, height: 38, radius: 12),
    SizedBox(width: 14),
    Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SkeletonBox(width: 220, height: 14, radius: 7),
      SizedBox(height: 10),
      SkeletonBox(width: 130, height: 18, radius: 10),
      SizedBox(height: 8),
      SkeletonBox(width: 200, height: 12, radius: 6),
      SizedBox(height: 6),
      SkeletonBox(width: 150, height: 12, radius: 6),
    ])),
  ]));
}
