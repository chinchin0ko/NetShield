// Pure Dart builders for the Windows privileged steps (firewall +
// WireGuard). No Flutter, no I/O: both the app (WindowsVpn) and the
// Windows Service (bin/netshield_service.dart) build the same scripts
// from here, so the service and the app can never drift apart.
//
// The exit codes are the contract between the scripts and their caller:
// 0 = ok, 10 = the firewall lock failed, 20 = the tunnel install failed.

/// Exit codes for the combined admin scripts: the script exits with the
/// code of the first step that failed, so the caller knows what broke
/// and whether the traffic lock is already on.
class WindowsAdminExit {
  static const ok = 0;
  static const firewallFailed = 10;
  static const tunnelFailed = 20;
}

class WindowsAdminCommands {
  static const rulePrefix = 'NetShield Killswitch';

  /// Tailscale controlplane + DERP nodes (IPv4), fetched from the DERP map
  /// on 2026-11-22. Only used when the SSH exception is explicitly enabled
  /// (Ajustes > Permitir conexiones SSH).
  static const tailscaleInfraIps = <String>[
    '102.67.165.185', '102.67.165.36', '102.67.165.90', '102.67.167.188',
    '102.67.167.245', '102.67.167.37', '103.6.84.152', '157.180.28.32',
    '162.248.221.199', '162.248.221.215', '162.248.221.248', '167.235.72.200',
    '172.105.166.103', '172.105.169.57', '172.105.179.230', '172.236.162.33',
    '172.236.162.40', '172.236.162.42', '172.237.28.183', '172.237.61.190',
    '172.237.61.194', '172.237.61.197', '172.237.66.30', '172.237.72.43',
    '172.237.72.79', '172.237.72.8', '172.238.6.179', '172.238.6.180',
    '172.238.6.34', '176.58.88.183', '176.58.90.104', '176.58.90.147',
    '176.58.90.207', '176.58.92.144', '176.58.92.254', '176.58.93.147',
    '176.58.93.154', '176.58.93.248', '178.156.134.232', '178.156.152.106',
    '178.156.152.91', '185.178.202.101', '185.178.202.33', '185.34.3.207',
    '185.34.3.232', '185.34.3.75', '185.40.234.113', '185.40.234.176',
    '185.40.234.219', '185.40.234.53', '185.40.234.77', '192.73.240.121',
    '192.73.240.132', '192.73.240.161', '192.73.242.187', '192.73.242.204',
    '192.73.242.28', '192.73.243.135', '192.73.243.141', '192.73.243.229',
    '192.73.244.245', '192.73.248.83', '192.73.252.134', '192.73.252.65',
    '198.18.186.205', '199.38.181.103', '199.38.181.104', '199.38.181.71',
    '199.38.181.93', '199.38.182.118', '205.147.105.30', '205.147.105.78',
    '208.111.34.178', '208.111.40.12', '208.111.40.216', '208.72.155.133',
    '208.83.233.233', '208.83.234.151', '209.177.145.118', '209.177.145.120',
    '209.177.156.197', '209.177.156.94', '209.177.158.15', '209.177.158.246',
    '45.159.97.144', '45.159.97.233', '45.159.97.61', '45.159.98.145',
    '45.159.98.196', '45.159.98.253', '46.62.141.44', '49.12.193.137',
    '49.13.204.141', '5.161.218.233', '65.109.143.62', '95.217.2.165',
  ];

  /// The Windows default: every profile allows outbound traffic.
  static const allAllow = {
    'Domain': 'Allow',
    'Private': 'Allow',
    'Public': 'Allow',
  };

  /// Firewall rules that turn the traffic lock on. Pure: no I/O, so the
  /// connect flow can run them inside its single combined admin script.
  static List<String> killswitchEnableCommands(String tunnel, String endpoint,
      {bool allowSsh = false, bool includeTunnelRule = true}) {
    final commands = <String>[
      'Remove-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue',
      'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block',
      if (includeTunnelRule) _tunnelRule(tunnel),
      'New-NetFirewallRule -DisplayName "$rulePrefix (servidor)" -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $endpoint -Profile Any | Out-Null',
      'New-NetFirewallRule -DisplayName "$rulePrefix (DHCP)" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any | Out-Null',
    ];
    if (allowSsh) {
      // SSH exception (opt-in, Ajustes > Permitir conexiones SSH): Tailscale
      // carries the inbound SSH session, so its interface, its WireGuard UDP
      // port and TCP 443 to its infrastructure must be allowed.
      final infra = tailscaleInfraIps.join(',');
      commands.add(
          'New-NetFirewallRule -DisplayName "$rulePrefix (SSH)" -Direction Outbound -Action Allow -InterfaceAlias "Tailscale" -Profile Any | Out-Null');
      commands.add(
          'New-NetFirewallRule -DisplayName "$rulePrefix (SSH UDP)" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 41641 -Profile Any | Out-Null');
      commands.add(
          'New-NetFirewallRule -DisplayName "$rulePrefix (SSH TCP)" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 -RemoteAddress $infra -Profile Any | Out-Null');
    }
    return commands;
  }

  static String _tunnelRule(String tunnel) =>
      'New-NetFirewallRule -DisplayName "$rulePrefix (tunel)" -Direction Outbound -Action Allow -InterfaceAlias "$tunnel" -Profile Any | Out-Null';

  static String _psLiteral(String value) => "'${value.replaceAll("'", "''")}'";

  // Windows PowerShell can return before a GUI-subsystem executable exits.
  // Wait for WireGuard explicitly and read the exit code from that process.
  static String _runWireGuard(String exe, String operation, String argument) =>
      '\$wireGuard = Start-Process -FilePath ${_psLiteral(exe)} '
      '-ArgumentList ${_psLiteral(operation)},${_psLiteral('"$argument"')} '
      '-NoNewWindow -Wait -PassThru -ErrorAction Stop';

  /// Firewall rules that turn the traffic lock off. Pure, like above.
  /// When [original] holds the per-profile DefaultOutboundAction captured
  /// before the lock went on, each profile goes back to its own value
  /// instead of a blanket Allow (a profile that was already Block stays
  /// Block). Without a snapshot (old lock files), every profile goes
  /// back to Allow, the Windows default.
  static List<String> killswitchDisableCommands(
      {Map<String, String>? original}) {
    final commands = <String>[
      'Remove-NetFirewallRule -DisplayName "$rulePrefix*" -ErrorAction SilentlyContinue',
    ];
    if (original != null && original.isNotEmpty) {
      for (final entry in original.entries) {
        final value = restoreAction(entry.value);
        commands.add(
            'Set-NetFirewallProfile -Profile ${entry.key} -DefaultOutboundAction $value');
      }
    } else {
      commands.add(
          'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow');
    }
    return commands;
  }

  /// A DefaultOutboundAction value that is safe to restore. Anything that
  /// is not Allow, Block or NotConfigured falls back to Allow.
  static String restoreAction(String value) {
    final v = value.trim().toLowerCase();
    if (v == 'block') return 'Block';
    if (v == 'notconfigured') return 'NotConfigured';
    return 'Allow';
  }

  /// One elevated script for connect: traffic lock first (so nothing leaks
  /// while the tunnel comes up), then the tunnel install and its allow rule. Exits
  /// [WindowsAdminExit.firewallFailed] if the lock fails,
  /// [WindowsAdminExit.tunnelFailed] if the install fails,
  /// [WindowsAdminExit.ok] when both succeed. Pure and testable.
  static List<String> connectAdminScript(String tunnel, String endpoint,
      String wireguardExe, String configPath, {bool allowSsh = false}) => [
        r"$ErrorActionPreference = 'Stop'",
        'try {',
        ...killswitchEnableCommands(tunnel, endpoint,
            allowSsh: allowSsh, includeTunnelRule: false),
        '} catch { Write-Error -ErrorRecord \$_ -ErrorAction Continue; exit ${WindowsAdminExit.firewallFailed} }',
        'try {',
        _runWireGuard(wireguardExe, '/installtunnelservice', configPath),
        r'if ($wireGuard.ExitCode -ne 0) { throw "WireGuard install exit $($wireGuard.ExitCode)." }',
        '} catch { Write-Error -ErrorRecord \$_ -ErrorAction Continue; exit ${WindowsAdminExit.tunnelFailed} }',
        // WireGuard creates its adapter asynchronously after installation.
        // Keep outbound traffic blocked while waiting for its interface.
        r'$deadline = [DateTime]::UtcNow.AddSeconds(15)',
        'while (-not (Get-NetAdapter -Name "$tunnel" -ErrorAction SilentlyContinue)) {',
        '  if ([DateTime]::UtcNow -ge \$deadline) {',
        '    Write-Error "WireGuard adapter $tunnel did not appear." -ErrorAction Continue',
        '    exit ${WindowsAdminExit.tunnelFailed}',
        '  }',
        '  Start-Sleep -Milliseconds 250',
        '}',
        'try {',
        _tunnelRule(tunnel),
        '} catch { Write-Error -ErrorRecord \$_ -ErrorAction Continue; exit ${WindowsAdminExit.firewallFailed} }',
        'exit ${WindowsAdminExit.ok}',
      ];

  /// One elevated script for disconnect: uninstall the tunnel service and
  /// restore the firewall, best effort on both steps, exiting with the
  /// first failure code ([WindowsAdminExit.tunnelFailed] or
  /// [WindowsAdminExit.firewallFailed]). Only the steps the caller asks
  /// for are included. Pure and testable.
  static List<String> disconnectAdminScript(
      {required bool uninstallTunnel,
      required String wireguardExe,
      required String tunnel,
      required bool disableKillswitch,
      Map<String, String>? original}) {
    final script = <String>[
      r"$ErrorActionPreference = 'Stop'",
      r'$fail = 0',
    ];
    if (uninstallTunnel) {
      script.addAll([
        'try {',
        _runWireGuard(wireguardExe, '/uninstalltunnelservice', tunnel),
        r'if ($wireGuard.ExitCode -ne 0) { throw "WireGuard uninstall exit $($wireGuard.ExitCode)." }',
        '} catch { \$fail = ${WindowsAdminExit.tunnelFailed} }',
      ]);
    }
    if (disableKillswitch) {
      script.addAll([
        'try {',
        ...killswitchDisableCommands(original: original),
        '} catch { if (\$fail -eq 0) { \$fail = ${WindowsAdminExit.firewallFailed} } }',
      ]);
    }
    script.add(r'exit $fail');
    return script;
  }
}
