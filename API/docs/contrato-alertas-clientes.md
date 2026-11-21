# Contrato de alertas para clientes

La API de desarrollo se accede por HTTPS en `https://api.netshield.lat`. Los clientes envían `Authorization: Bearer <token>` obtenido en `POST /auth/token`. Las operaciones de alertas solo actúan sobre la cuenta autenticada y las respuestas incluyen `Cache-Control: no-store`.

## Consultar alertas

`GET /security/alerts` devuelve hasta 50 eventos, del más reciente al más antiguo:

```json
{
  "monitoring": "experimental",
  "alerts": [{
    "id": 123,
    "device_id": "0123456789abcdef0123456789abcdef",
    "occurred_at": "2026-11-21T08:00:00Z",
    "signature": "ET MALWARE ejemplo",
    "severity": 2,
    "review_status": "new",
    "reviewed_at": null
  }]
}
```

`monitoring` es `experimental` si se recibió un heartbeat reciente y `not_active` si no. Por compatibilidad se conserva el valor `experimental`; el cliente puede mostrar «Sensor comunicado recientemente», sin inferir que se detectan todas las amenazas o que no hay pérdida de paquetes. Una lista vacía no indica que no existan amenazas. Una alerta es un indicador y no una confirmación de infección. Suricata asigna severidad 1 como más alta y 3 como más baja en las categorías habituales; la API acepta valores de 1 a 255 y el cliente no debe asumir que solo existirán tres.

`device_id` identifica el dispositivo de la cuenta, `occurred_at` es el instante del sensor con zona horaria, y `id` es un identificador para revisión. Las marcas `review_status` son `new`, `reviewed` o `false_positive`. Esta última expresa una valoración del usuario, no un resultado automático. `reviewed_at` es nulo cuando el estado es `new`.

## Revisar una alerta

`POST /security/alerts/{id}/review` acepta JSON `{"status":"reviewed"}`, `{"status":"false_positive"}` o `{"status":"new"}` y responde `204` si la operación tuvo éxito. Cada cambio real queda registrado con su fecha. Un `404` indica que el identificador no existe o no pertenece a la cuenta; `422` indica un cuerpo inválido; `401`, una sesión inválida; `503`, indisponibilidad. Tras guardar, el cliente puede actualizar la lista con `GET /security/alerts`.

`POST /security/alerts/test` es opcional y exclusivo de entornos de desarrollo donde se habilite expresamente. Sus alertas están marcadas como prueba y no representan amenazas reales; un cliente debe tolerar `404` cuando el servidor no lo habilite.

## Entrega y eventos retenidos

El sensor entrega lotes con reintento y la API deduplica. Los eventos sin atribución segura se conservan en una cola restringida y se reevalúan en lotes en cada heartbeat. No se exponen a ninguna cuenta hasta que cumplen las mismas comprobaciones de propiedad que los eventos nuevos. Si el propietario no puede comprobarse, el evento se conserva para inspección operativa. La herramienta administrativa de solo lectura `python -m app.sensor_queue_status` muestra la cantidad retenida; la opción `--details` incluye IP y firmas sensibles y debe ejecutarse solamente en el entorno de administración autorizado.
