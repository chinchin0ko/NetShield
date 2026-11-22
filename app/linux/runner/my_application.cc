#include "my_application.h"

#include <flutter_linux/flutter_linux.h>
#include <libayatana-appindicator/app-indicator.h>

#include "flutter/generated_plugin_registrant.h"

struct _MyApplication {
  GtkApplication parent_instance;
  char** dart_entrypoint_arguments;
  AppIndicator* indicator;
  FlMethodChannel* tray_channel;
  GtkWindow* window;
  bool first_frame_received;
};

G_DEFINE_TYPE(MyApplication, my_application, GTK_TYPE_APPLICATION)

// Called when first Flutter frame received.
static void first_frame_cb(MyApplication* self, FlView* view) {
  // Restoring the render surface can emit first-frame again. Only show on startup.
  if (!self->first_frame_received) {
    self->first_frame_received = true;
    gtk_widget_show(gtk_widget_get_toplevel(GTK_WIDGET(view)));
  }
}

// Keep the window recoverable on desktops without a system tray.
static gboolean tray_available() {
  g_autoptr(GError) error = nullptr;
  g_autoptr(GDBusConnection) bus = g_bus_get_sync(G_BUS_TYPE_SESSION, nullptr, &error);
  if (bus == nullptr) return FALSE;
  g_autoptr(GVariant) reply = g_dbus_connection_call_sync(
      bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
      "org.freedesktop.DBus", "NameHasOwner",
      g_variant_new("(s)", "org.kde.StatusNotifierWatcher"),
      G_VARIANT_TYPE("(b)"), G_DBUS_CALL_FLAGS_NONE, 1000, nullptr, nullptr);
  gboolean available = FALSE;
  if (reply != nullptr) g_variant_get(reply, "(b)", &available);
  return available;
}

static void restore_window(MyApplication* self) {
  gtk_window_set_skip_taskbar_hint(self->window, FALSE);
  gtk_widget_show(GTK_WIDGET(self->window));
  gtk_window_deiconify(self->window);
  gtk_window_present(self->window);
  gtk_widget_queue_draw(GTK_WIDGET(self->window));
}

static void show_window(GtkMenuItem*, gpointer data) {
  restore_window(MY_APPLICATION(data));
}

static void quit_all_finished(GObject* source, GAsyncResult* result, gpointer data) {
  MyApplication* self = MY_APPLICATION(data);
  g_autoptr(GError) error = nullptr;
  g_autoptr(FlMethodResponse) response = fl_method_channel_invoke_method_finish(
      FL_METHOD_CHANNEL(source), result, &error);
  if (response != nullptr && FL_IS_METHOD_SUCCESS_RESPONSE(response)) {
    g_application_quit(G_APPLICATION(self));
    return;
  }
  restore_window(self);
  GtkWidget* dialog = gtk_message_dialog_new(self->window, GTK_DIALOG_MODAL,
      GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
      "No se pudo desconectar la VPN y desactivar el bloqueo. La aplicación seguirá abierta; revisa su estado e inténtalo de nuevo.");
  g_signal_connect(dialog, "response", G_CALLBACK(gtk_widget_destroy), nullptr);
  gtk_widget_show(dialog);
}

static void quit_all(GtkMenuItem*, gpointer data) {
  MyApplication* self = MY_APPLICATION(data);
  fl_method_channel_invoke_method(self->tray_channel, "disconnectAndQuit", nullptr,
                                  nullptr, quit_all_finished, self);
}

static void hide_window(GtkMenuItem*, gpointer data) {
  MyApplication* self = MY_APPLICATION(data);
  if (tray_available()) {
    // Keep the GtkWindow, FlView and Dart isolate alive: login, monitoring and
    // VPN state must survive closing the window. Never call quit or destroy.
    gtk_widget_hide(GTK_WIDGET(self->window));
  } else {
    gtk_window_iconify(self->window);
  }
}

static gboolean on_window_close(GtkWidget*, GdkEvent*, gpointer data) {
  hide_window(nullptr, data);
  return TRUE;
}

static void setup_indicator(MyApplication* self) {
  G_GNUC_BEGIN_IGNORE_DEPRECATIONS
  self->indicator = app_indicator_new("netshield-vpn", "netshield",
                                      APP_INDICATOR_CATEGORY_APPLICATION_STATUS);
  G_GNUC_END_IGNORE_DEPRECATIONS
  GtkWidget* menu = gtk_menu_new();
  GtkWidget* open = gtk_menu_item_new_with_label("Abrir NetShield");
  GtkWidget* hide = gtk_menu_item_new_with_label("Ocultar ventana (mantener VPN)");
  GtkWidget* quit_everything = gtk_menu_item_new_with_label("Desconectar VPN y salir");
  g_signal_connect(open, "activate", G_CALLBACK(show_window), self);
  g_signal_connect(hide, "activate", G_CALLBACK(hide_window), self);
  g_signal_connect(quit_everything, "activate", G_CALLBACK(quit_all), self);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), open);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), hide);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), quit_everything);
  gtk_widget_show_all(menu);
  app_indicator_set_menu(self->indicator, GTK_MENU(menu));
  app_indicator_set_title(self->indicator, "NetShield VPN");
  app_indicator_set_status(self->indicator, APP_INDICATOR_STATUS_ACTIVE);
}

// Implements GApplication::activate.
static void my_application_activate(GApplication* application) {
  MyApplication* self = MY_APPLICATION(application);
  GList* windows = gtk_application_get_windows(GTK_APPLICATION(application));
  if (windows != nullptr) {
    restore_window(self);
    return;
  }

  GtkWindow* window =
      GTK_WINDOW(gtk_application_window_new(GTK_APPLICATION(application)));
  gtk_window_set_default_size(window, 1280, 720);

  // If you want to use a header bar, uncomment the following lines.
  // Header bars are commonly used in GNOME based desktop environments and
  // allow additional widgets to be added to the title bar.
  // See https://docs.gtk.org/gtk3/class.HeaderBar.html
  // GtkHeaderBar* header_bar = GTK_HEADER_BAR(gtk_header_bar_new());
  // gtk_widget_show(GTK_WIDGET(header_bar));
  // gtk_header_bar_set_show_close_button(header_bar, TRUE);
  // gtk_window_set_titlebar(window, GTK_WIDGET(header_bar));

  gtk_window_set_title(window, "NetShield VPN");
  gtk_window_set_icon_name(window, "netshield");
  self->window = window;
  setup_indicator(self);
  g_signal_connect(window, "delete-event", G_CALLBACK(on_window_close), self);

  g_autoptr(FlDartProject) project = fl_dart_project_new();
  fl_dart_project_set_dart_entrypoint_arguments(
      project, self->dart_entrypoint_arguments);

  FlView* view = fl_view_new(project);
  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  self->tray_channel = fl_method_channel_new(
      fl_engine_get_binary_messenger(fl_view_get_engine(view)),
      "netshield/linux_tray", FL_METHOD_CODEC(codec));
  GdkRGBA background_color;
  // Background defaults to black, override it here if necessary, e.g. #00000000
  // for transparent.
  gdk_rgba_parse(&background_color, "#000000");
  fl_view_set_background_color(view, &background_color);
  gtk_widget_show(GTK_WIDGET(view));
  gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(view));

  // Show the window when Flutter renders.
  // Requires the view to be realized so we can start rendering.
  g_signal_connect_swapped(view, "first-frame", G_CALLBACK(first_frame_cb),
                           self);
  gtk_widget_realize(GTK_WIDGET(view));

  fl_register_plugins(FL_PLUGIN_REGISTRY(view));

  gtk_widget_grab_focus(GTK_WIDGET(view));
}

// Implements GApplication::local_command_line.
static gboolean my_application_local_command_line(GApplication* application,
                                                  gchar*** arguments,
                                                  int* exit_status) {
  MyApplication* self = MY_APPLICATION(application);
  // Strip out the first argument as it is the binary name.
  self->dart_entrypoint_arguments = g_strdupv(*arguments + 1);

  g_autoptr(GError) error = nullptr;
  if (!g_application_register(application, nullptr, &error)) {
    g_warning("Failed to register: %s", error->message);
    *exit_status = 1;
    return TRUE;
  }

  g_application_activate(application);
  *exit_status = 0;

  return TRUE;
}

// Implements GApplication::startup.
static void my_application_startup(GApplication* application) {
  // MyApplication* self = MY_APPLICATION(object);

  // Perform any actions required at application startup.

  G_APPLICATION_CLASS(my_application_parent_class)->startup(application);
}

// Implements GApplication::shutdown.
static void my_application_shutdown(GApplication* application) {
  // MyApplication* self = MY_APPLICATION(object);

  // Perform any actions required at application shutdown.

  G_APPLICATION_CLASS(my_application_parent_class)->shutdown(application);
}

// Implements GObject::dispose.
static void my_application_dispose(GObject* object) {
  MyApplication* self = MY_APPLICATION(object);
  g_clear_pointer(&self->dart_entrypoint_arguments, g_strfreev);
  g_clear_object(&self->indicator);
  g_clear_object(&self->tray_channel);
  G_OBJECT_CLASS(my_application_parent_class)->dispose(object);
}

static void my_application_class_init(MyApplicationClass* klass) {
  G_APPLICATION_CLASS(klass)->activate = my_application_activate;
  G_APPLICATION_CLASS(klass)->local_command_line =
      my_application_local_command_line;
  G_APPLICATION_CLASS(klass)->startup = my_application_startup;
  G_APPLICATION_CLASS(klass)->shutdown = my_application_shutdown;
  G_OBJECT_CLASS(klass)->dispose = my_application_dispose;
}

static void my_application_init(MyApplication* self) {}

MyApplication* my_application_new() {
  // Set the program name to the application ID, which helps various systems
  // like GTK and desktop environments map this running application to its
  // corresponding .desktop file. This ensures better integration by allowing
  // the application to be recognized beyond its binary name.
  g_set_prgname(APPLICATION_ID);

  return MY_APPLICATION(g_object_new(my_application_get_type(),
                                     "application-id", APPLICATION_ID, "flags",
                                     static_cast<GApplicationFlags>(0), nullptr));
}
