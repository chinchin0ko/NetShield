# Ocultar y restaurar NetShield en Linux

La equis y «Ocultar ventana (mantener VPN)» ocultan la ventana sin destruir `GtkWindow`, `FlView` ni el estado de Dart. El icono de bandeja permanece activo. «Abrir NetShield» y abrir de nuevo el lanzador recuperan la misma ventana. La única salida del menú es «Desconectar VPN y salir»; espera la desconexión y desactivación del bloqueo antes de terminar el proceso.

Sin bandeja disponible, la equis minimiza la ventana para que siga siendo recuperable. En KDE se prefiere XWayland, dado que la restauración desde la bandeja con GTK 3 sobre Wayland nativo falló en este equipo. Se respeta una selección explícita de `GDK_BACKEND`.

## Comprobación del 22 de noviembre de 2026

Se compiló un ejecutable de prueba con el mismo runner nativo y los widgets reales. API, VPN y notificador fueron sustituidos por implementaciones locales de prueba; no se utilizaron credenciales reales ni se modificó la VPN del usuario. El programa inició sesión por el flujo habitual de la interfaz una sola vez.

Sobre KDE/XWayland se ejecutaron tres ciclos:

1. Cerrar mediante la acción de cierre de KWin (la misma que la equis) y restaurar mediante el menú D-Bus de la bandeja.
2. Ocultar mediante el menú de bandeja y restaurar desde el mismo menú.
3. Repetir el cierre de KWin y la restauración.

En cada ciclo se verificó que la ventana desaparecía de `_NET_CLIENT_LIST` al ocultarse y regresaba al restaurarse. El proceso mantuvo el mismo PID, el contador de login permaneció en uno y la interfaz conservó el saludo de la cuenta autenticada. Las capturas de la ventana antes y después fueron idénticas, descartando la pantalla negra en esta prueba. También se comprobó la salida del programa por «Desconectar VPN y salir» con los servicios simulados.

Antes de empaquetar se recompiló expresamente `lib/main.dart`, el punto de entrada real. El ejecutable de prueba no se incluye en el paquete. Esta prueba no valida la persistencia de una sesión después de terminar el proceso o reiniciar el sistema, ni sustituye una prueba de tráfico VPN real.
