// NetShield Windows Service wrapper (netshield-service.exe).
//
// The Dart service (netshield-server.exe) cannot run as a real Windows
// service: its ServiceMain uses Pointer.fromFunction, which may only be
// invoked on the isolate's mutator thread, but the SCM calls ServiceMain
// on its own dispatcher thread -> the process aborts (0xc0000409, exit
// 1067). See SERVICE_CRASH.md.
//
// This small native wrapper implements ServiceMain and the control
// handler in C (no FFI) and launches netshield-server.exe --console as
// a child process (running as SYSTEM, like the wrapper). On STOP or
// SHUTDOWN it kills the child and reports SERVICE_STOPPED.
//
// The wrapper IS the binary registered with the SCM:
//   sc.exe create NetShieldService binPath= "C:\Program Files\NetShield\netshield-service.exe" start= auto obj= LocalSystem DisplayName= "NetShield Service"
// It expects netshield-server.exe in the same directory, and writes the
// child's stdout/stderr to netshield-server.log next to it (the service
// has no console, so an unredirected stdout would make the Dart child
// fail its first write).
//
// Build (from a Visual Studio x64 Native Tools prompt, or after
// vcvarsall.bat x64):
//   cl.exe /nologo /O2 /W3 /Fe:netshield-service.exe netshield_service_wrapper.c advapi32.lib
//
// The app (windows_vpn.dart _ensureService) and the installer
// (netshield.iss) already install netshield-service.exe as the service;
// they need no change for the wrapper, they just get a different binary
// under the same name. The Dart server is a separate exe now
// (netshield-server.exe), compiled with:
//   dart compile exe bin/netshield_service.dart -o build\service\netshield-server.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define SERVICE_NAME L"NetShieldService"
#define SERVER_EXE_NAME L"netshield-server.exe"
#define SERVER_LOG_NAME L"netshield-server.log"

static SERVICE_STATUS_HANDLE g_statusHandle = NULL;
static SERVICE_STATUS g_status;
static HANDLE g_hStopEvent = NULL;
static HANDLE g_hChild = NULL;

/* Report the service status to the SCM. */
static void reportStatus(DWORD currentState, DWORD win32ExitCode,
                         DWORD waitHint) {
  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwCurrentState = currentState;
  g_status.dwControlsAccepted =
      (currentState == SERVICE_RUNNING)
          ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
          : 0;
  g_status.dwWin32ExitCode = win32ExitCode;
  g_status.dwServiceSpecificExitCode = 0;
  g_status.dwCheckPoint =
      (currentState == SERVICE_START_PENDING ||
       currentState == SERVICE_STOP_PENDING)
          ? 1
          : 0;
  g_status.dwWaitHint = waitHint;
  if (g_statusHandle != NULL) {
    SetServiceStatus(g_statusHandle, &g_status);
  }
}

/* Control handler: STOP / SHUTDOWN -> signal the stop event so
 * ServiceMain terminates the child and reports STOPPED. */
static void WINAPI serviceCtrlHandler(DWORD control) {
  switch (control) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
    reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    if (g_hStopEvent != NULL) {
      SetEvent(g_hStopEvent);
    }
    break;
  case SERVICE_CONTROL_INTERROGATE:
    if (g_statusHandle != NULL) {
      SetServiceStatus(g_statusHandle, &g_status);
    }
    break;
  default:
    break;
  }
}

/* Build "<dir>\<name>" where <dir> is the directory of this exe.
 * Returns 1 on success, 0 on failure. */
static int buildSiblingPath(WCHAR *out, size_t outChars,
                            const WCHAR *name) {
  WCHAR path[MAX_PATH];
  DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);
  WCHAR *slash;
  size_t dirLen;
  if (len == 0 || len >= MAX_PATH) {
    return 0;
  }
  slash = wcsrchr(path, L'\\');
  if (slash == NULL) {
    return 0;
  }
  dirLen = (size_t)(slash - path) + 1; /* include trailing backslash */
  if (dirLen + wcslen(name) + 1 > outChars) {
    return 0;
  }
  wcsncpy_s(out, outChars, path, dirLen);
  out[dirLen] = L'\0';
  wcscat_s(out, outChars, name);
  return 1;
}

static void WINAPI serviceMain(DWORD argc, LPWSTR *argv) {
  WCHAR serverPath[MAX_PATH];
  WCHAR logPath[MAX_PATH];
  WCHAR dir[MAX_PATH];
  WCHAR cmdLine[MAX_PATH + 32];
  SECURITY_ATTRIBUTES sa;
  HANDLE hLog = INVALID_HANDLE_VALUE;
  HANDLE hNul = INVALID_HANDLE_VALUE;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  WCHAR *slash;
  BOOL ok;

  (void)argc;
  (void)argv;

  g_statusHandle =
      RegisterServiceCtrlHandlerW(SERVICE_NAME, serviceCtrlHandler);
  if (g_statusHandle == NULL) {
    return;
  }
  reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

  /* Locate the Dart server and its log next to this wrapper. */
  if (!buildSiblingPath(serverPath, MAX_PATH, SERVER_EXE_NAME) ||
      !buildSiblingPath(logPath, MAX_PATH, SERVER_LOG_NAME)) {
    reportStatus(SERVICE_STOPPED, ERROR_FILE_NOT_FOUND, 0);
    return;
  }

  g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (g_hStopEvent == NULL) {
    reportStatus(SERVICE_STOPPED, GetLastError(), 0);
    return;
  }

  /* Redirect the child's stdout/stderr to a log file. The service has
   * no console, so an unredirected stdout would make the Dart child
   * fail its first write. Truncate the log on each start. stdin comes
   * from NUL (the server never reads it). */
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;
  hLog = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, &sa,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hLog == INVALID_HANDLE_VALUE) {
    reportStatus(SERVICE_STOPPED, GetLastError(), 0);
    return;
  }
  hNul = CreateFileW(L"NUL", GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hNul == INVALID_HANDLE_VALUE) {
    CloseHandle(hLog);
    reportStatus(SERVICE_STOPPED, GetLastError(), 0);
    return;
  }

  /* Command line: "<serverPath>" --console (mutable buffer, quoted,
   * because the path may contain spaces, e.g. Program Files). */
  if (swprintf_s(cmdLine, MAX_PATH + 32, L"\"%s\" --console",
                 serverPath) < 0) {
    CloseHandle(hLog);
    CloseHandle(hNul);
    reportStatus(SERVICE_STOPPED, ERROR_BUFFER_OVERFLOW, 0);
    return;
  }

  /* Working directory = the wrapper's directory. */
  wcscpy_s(dir, MAX_PATH, serverPath);
  slash = wcsrchr(dir, L'\\');
  if (slash != NULL) {
    *slash = L'\0';
  }

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = hNul;
  si.hStdOutput = hLog;
  si.hStdError = hLog;

  ZeroMemory(&pi, sizeof(pi));
  ok = CreateProcessW(serverPath, cmdLine, NULL, NULL, TRUE,
                      CREATE_NO_WINDOW, NULL, dir, &si, &pi);
  /* The log and NUL handles are now owned by the child (inherited);
   * close our copies. */
  CloseHandle(hLog);
  CloseHandle(hNul);
  if (!ok) {
    reportStatus(SERVICE_STOPPED, GetLastError(), 0);
    return;
  }
  g_hChild = pi.hProcess;
  CloseHandle(pi.hThread);

  reportStatus(SERVICE_RUNNING, NO_ERROR, 0);

  /* Wait until the SCM asks us to stop, or the child exits. */
  {
    HANDLE waitHandles[2] = {g_hStopEvent, g_hChild};
    DWORD w = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
    if (w == WAIT_OBJECT_0) {
      /* SCM asked us to stop: kill the child if it is still alive. */
      DWORD exitCode = 0;
      reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
      if (GetExitCodeProcess(g_hChild, &exitCode) &&
          exitCode == STILL_ACTIVE) {
        TerminateProcess(g_hChild, 1);
      }
      WaitForSingleObject(g_hChild, 5000);
      CloseHandle(g_hChild);
      g_hChild = NULL;
      reportStatus(SERVICE_STOPPED, NO_ERROR, 0);
    } else {
      /* The child died on its own: the service cannot serve, so it
       * stops and reports the child's exit code. */
      DWORD exitCode = 0;
      GetExitCodeProcess(g_hChild, &exitCode);
      CloseHandle(g_hChild);
      g_hChild = NULL;
      reportStatus(SERVICE_STOPPED,
                   exitCode != 0 ? exitCode : ERROR_PROCESS_ABORTED,
                   0);
    }
  }
}

int main(void) {
  SERVICE_TABLE_ENTRYW table[2];

  table[0].lpServiceName = (LPWSTR)SERVICE_NAME;
  table[0].lpServiceProc = serviceMain;
  table[1].lpServiceName = NULL;
  table[1].lpServiceProc = NULL;

  if (!StartServiceCtrlDispatcherW(table)) {
    /* Not started by the SCM (run by hand). Report and exit; this exe
     * only runs as a service. */
    DWORD err = GetLastError();
    fprintf(stderr,
            "netshield-service: StartServiceCtrlDispatcher failed "
            "(%lu). This exe must be run as a Windows service "
            "(sc.exe start NetShieldService).\n",
            (unsigned long)err);
    return (int)err;
  }
  return 0;
}
