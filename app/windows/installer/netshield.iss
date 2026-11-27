; NetShield VPN — instalador de Windows (Inno Setup).
; Genera un setup.exe (no un .zip) que instala la app gráfica, el CLI
; (netshield.exe) y el servicio de Windows (el wrapper C
; netshield-service.exe, que lanza netshield-server.exe, el servidor
; Dart). Se compila en la CI después de `flutter build windows`
; y de compilar el CLI a build\windows\x64\runner\Release\netshield.exe,
; el servidor Dart a build\service\netshield-server.exe y el wrapper
; a build\service\netshield-service.exe.
; Uso local: iscc netshield.iss   (desde esta carpeta)

#define AppVersion "0.1.0"
#define AppName "NetShield VPN"

[Setup]
AppId={{3F7A2B1C-9D4E-4A8F-B6C2-1E5A8D3F7B9A}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=NetShield
AppPublisherURL=https://netshield.lat
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\installer-output
OutputBaseFilename=netshield-setup-{#AppVersion}
SetupIconFile=..\runner\resources\app_icon.ico
WizardSmallImageFile=..\runner\resources\wizard-small.bmp
WizardImageFile=..\runner\resources\wizard-image.bmp
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\netshield_app.exe

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; GroupDescription: "Accesos directos:"; Flags: unchecked

[Files]
; Todo el bundle de Flutter (la app) más el CLI, que la CI deja en Release\.
Source: "..\..\build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
; Servicio de Windows: el wrapper en C (netshield-service.exe) es el
; binario que registra el SCM; lanza netshield-server.exe (el servidor
; Dart) como hijo. Ambos los compila la CI a build\service\
; (ver .github/workflows/build-windows.yml). La app los usa para
; ejecutar con privilegios sin pedir UAC al conectar.
Source: "..\..\build\service\netshield-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\build\service\netshield-server.exe"; DestDir: "{app}"; Flags: ignoreversion
; Atajo corto nsv para el CLI.
Source: "nsv.bat"; DestDir: "{app}"; Flags: ignoreversion
; Instalador MSI de WireGuard (lo descarga la CI a esta carpeta). Se copia
; a {tmp} y se borra tras instalar; el [Run] lo instala en silencio antes
; de que la app se use por primera vez.
Source: "wireguard-amd64-1.1.1.msi"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall

[Run]
; Instala WireGuard para Windows en silencio (sin lanzar su GUI) solo si
; aún no está instalado. La app lo necesita para el túnel VPN.
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\wireguard-amd64-1.1.1.msi"" /qn /norestart DO_NOT_LAUNCH=1"; Check: NeedsWireGuard; Flags: runhidden waituntilterminated; StatusMsg: "Instalando WireGuard..."
; Crea y arranca el servicio de Windows (el wrapper en C,
; netshield-service.exe; el instalador ya corre como admin, así que
; no hay prompt extra). El servicio ejecuta los comandos con
; privilegios para que la app no pida UAC al conectar.
Filename: "{sys}\sc.exe"; Parameters: "create NetShieldService binPath= ""{app}\netshield-service.exe"" start= auto obj= LocalSystem DisplayName= ""NetShield Service"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start NetShieldService"; Flags: runhidden

[UninstallRun]
; Detiene y borra el servicio al desinstalar.
Filename: "{sys}\sc.exe"; Parameters: "stop NetShieldService"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete NetShieldService"; Flags: runhidden

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\netshield_app.exe"
Name: "{group}\Desinstalar {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\netshield_app.exe"; Tasks: desktopicon

[Registry]
; Añade la carpeta de instalación al PATH para que `netshield` (el CLI)
; funcione desde cualquier terminal. Se quita al desinstalar.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
// Añade {app} al PATH solo si aún no está, y lo quita al desinstalar.
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

// Instala WireGuard solo si aún no está (lo detecta por su ejecutable).
function NeedsWireGuard(): boolean;
begin
  Result := not FileExists(ExpandConstant('{pf}\WireGuard\wireguard.exe'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Path, AppDir: string;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then exit;
  AppDir := ExpandConstant('{app}');
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', Path) then
  begin
    P := Pos(';' + AppDir, Path);
    if P > 0 then
    begin
      Delete(Path, P, Length(AppDir) + 1);
      RegWriteExpandStringValue(HKEY_LOCAL_MACHINE,
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'Path', Path);
    end;
  end;
end;
