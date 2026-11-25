String formatBytes(int value) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  double amount = value.toDouble(); var index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return '${amount.toStringAsFixed(index == 0 ? 0 : 1)} ${units[index]}';
}

