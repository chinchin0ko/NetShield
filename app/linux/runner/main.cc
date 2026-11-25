#include "my_application.h"

int main(int argc, char** argv) {
  // GTK 3 on native Wayland cannot reliably restore a minimized window from
  // a status-notifier menu. Prefer X11/XWayland when available; fall back to
  // Wayland, and respect an explicit user choice of backend.
  g_setenv("GDK_BACKEND", "x11,wayland", FALSE);
  g_autoptr(MyApplication) app = my_application_new();
  return g_application_run(G_APPLICATION(app), argc, argv);
}
