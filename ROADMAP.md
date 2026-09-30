# Roadmap de `bbai`

> Plan de evolución del MVP hacia un workspace local de investigación de seguridad,
> trazable, extensible y siempre bajo control humano.

Este documento distingue entre:

- **comprometido:** trabajo funcional pendiente identificado en el MVP actual;
- **propuesto:** líneas de producto que requieren una decisión de arquitectura antes de
  incorporarse al plan de ejecución.

## Estado actual

El núcleo funcional del MVP se completó con findings revisables, sesiones persistidas,
exportación Markdown/JSON y migraciones Alembic. La búsqueda FTS5, `bbai doctor` y las
integraciones `gau`, `katana` y `nuclei` se incorporaron después; las tareas pendientes
continúan sin marcarse.

El MVP ya dispone de:

- instalación persistente y CLI `bbai`;
- asistente interactivo en el primer `bbai init` para seleccionar herramientas opcionales
  y Ollama/modelo;
- targets, scope y target activo;
- SQLite con SQLAlchemy;
- integración con Ollama;
- tool calling con aprobación humana;
- `http_inspect`, `http_headers`, `subfinder`, `ffuf`, `gau`, `katana` y `nuclei`;
- diagnóstico de workspace, SQLite/FTS5, Ollama, keyring, target y binarios opcionales;
- búsqueda SQLite FTS5 con filtros por artefacto, target, sesión, estado y severidad;
- política de scope, límites, `dry-run` y registro de ejecuciones;
- evidencias, observaciones e hipótesis;
- perfiles de autenticación con keyring;
- redacción de secretos antes de persistir o enviar contexto al modelo.

El flujo funcional actual es:

```text
Pregunta
  → Contexto persistido
  → Propuesta de herramienta
  → Validación de scope y política
  → Aprobación humana
  → Ejecución
  → Evidencia
  → Observación
  → Hipótesis
```

## Principios de evolución

1. **El investigador conserva el control.** Ninguna acción externa o potencialmente
   intrusiva se ejecuta sin una política explícita y aprobación humana.
2. **Cada resultado debe ser trazable.** Una conclusión debe poder remontarse a una
   ejecución, sus argumentos, su salida y las evidencias asociadas.
3. **Local-first y secreto mínimo.** Los datos sensibles permanecen localmente y nunca
   se envían al LLM sin redacción o autorización explícita.
4. **La autonomía se limita por diseño.** Automatizar la secuencia de pasos no equivale
   a permitir explotación autónoma.
5. **CLI antes que UI.** El dominio y las políticas deben ser sólidos y testeables antes
   de construir una interfaz que los consuma.

## Fase 1 — Findings y revisión humana

**Estado: completada.**

**Objetivo:** cerrar el ciclo entre hipótesis y resultado reportable.

- [x] Crear findings y enlazarlos con observaciones o hipótesis.
- [x] Añadir título, resumen, severidad, confianza, impacto, reproducción y mitigación.
- [x] Asociar findings con evidencias, observaciones, hipótesis y ejecuciones.
- [x] Implementar `finding list`, `finding show` y actualización controlada.
- [x] Añadir estados `draft`, `in_review`, `accepted`, `rejected` y `reported`.
- [x] Persistir notas y decisiones de revisión humana.
- [x] Impedir que un finding no aceptado aparezca en informes normales.
- [x] Añadir tests de transiciones de estado y de relaciones.

**Criterio de salida:** una persona puede revisar, aceptar o rechazar un finding y
obtener el historial completo que lo respalda.

## Fase 2 — Sesiones y continuidad de investigación

**Estado: núcleo completado; etiquetas y exportación de sesiones pendientes.**

**Objetivo:** convertir ejecuciones aisladas en investigaciones reanudables.

- [x] Crear sesiones por target y objetivo de investigación.
- [x] Persistir preguntas, respuestas, llamadas a herramientas, resultados y decisiones.
- [x] Asociar evidencias, observaciones, hipótesis y findings a sesiones.
- [x] Añadir notas manuales.
- [x] Implementar `session list`, `session show`, `session resume` y cierre.
- [x] Incluir eventos y notas recientes como contexto al reanudar una investigación.
- [ ] Añadir etiquetas, política de retención y exportación de sesiones.

**Criterio de salida:** una investigación puede pausarse y reanudarse conservando
contexto, decisiones y trazabilidad.

## Fase 3 — Reporting y exportación

**Estado: exportación básica completada; plantillas y previsualización avanzada pendientes.**

**Objetivo:** transformar el trabajo revisado en entregables utilizables.

- [x] Generar informes Markdown.
- [x] Generar informes JSON para integraciones.
- [x] Incluir únicamente findings aceptados/reportados salvo opción explícita de borradores.
- [x] Incorporar evidencias, impacto, severidad, pasos de reproducción y mitigación.
- [x] Añadir metadatos del target, sesión y perfil de autenticación sin exponer secretos.
- [ ] Añadir plantillas configurables por programa o equipo.
- [x] Implementar salida a pantalla y `--output` para exportar.
- [x] Redactar secretos de perfiles activos y cabeceras sensibles en el informe.

**Criterio de salida:** un investigador puede generar un informe reproducible y
compartible a partir de findings aceptados.

## Fase 4 — Persistencia, migraciones y búsqueda

**Estado: completada.**

**Objetivo:** hacer evolucionar el esquema y localizar conocimiento sin perder
compatibilidad.

- [x] Sustituir migraciones ad hoc por Alembic.
- [x] Versionar el esquema y adoptar bases SQLite existentes sin perder sus datos.
- [x] Añadir SQLite FTS5 para targets, evidencias, notas, observaciones, hipótesis y
  findings.
- [x] Implementar `bbai search`.
- [x] Añadir filtros por target, sesión, estado, severidad y tipo.
- [ ] Diseñar la interfaz de recuperación de contexto para una futura búsqueda semántica.
- [ ] Evaluar embeddings/RAG solo después de medir la utilidad de FTS5.

**Criterio de salida:** las instalaciones existentes migran de forma segura y el
investigador puede encontrar rápidamente cualquier artefacto relevante.

## Fase 5 — Autenticación avanzada y perfiles de ejecución

**Estado: uso autenticado de `ffuf` completado; resto pendiente.**

**Objetivo:** cubrir aplicaciones autenticadas reales sin convertir las credenciales en
datos de la investigación.

- [x] Aplicar headers autenticados a `ffuf`.
- [x] Redactar valores secretos de la salida de `ffuf`.
- [ ] Permitir expiración configurable desde CLI.
- [ ] Añadir perfiles explícitos `anonymous`, `user`, `admin` y equivalentes definidos
  por el investigador.
- [ ] Comparar resultados entre perfiles para detectar diferencias de autorización.
- [ ] Añadir importación manual de cookies con confirmación y redacción.
- [ ] Evaluar OAuth/SSO y refresh tokens sin automatizar MFA de forma insegura.
- [ ] Añadir diagnóstico claro cuando el keyring no esté disponible.
- [ ] Evaluar un almacén cifrado local como alternativa opt-in, nunca como fallback
  silencioso.

**Criterio de salida:** una investigación puede comparar de forma segura respuestas
anónimas y autenticadas, manteniendo secretos fuera de SQLite, evidencias y contexto
del modelo.

## Fase 6 — Herramientas e integraciones

**Estado: primera tanda completada; hardening y adaptadores pendientes.**

**Objetivo:** ampliar cobertura manteniendo una frontera de seguridad explícita.

- [ ] Definir una clasificación de herramientas: pasivas, lectura activa e intrusivas.
- [ ] Asociar a cada herramienta límites, permisos, riesgos y requisitos de aprobación.
- [x] Añadir health checks y diagnóstico de dependencias externas mediante `bbai doctor`.
- [x] Crear integraciones aisladas para `gau`, `katana` y `nuclei` con scope y límites.
- [ ] Añadir adaptadores para importar resultados estructurados comunes.
- [ ] Probar redirecciones, puertos, wildcards, IDN, URLs con credenciales y límites de
  scope.
- [ ] Añadir tests de integración con servidores HTTP locales y mocks de Ollama.
- [x] Implementar `bbai doctor`.

**Criterio de salida:** nuevas herramientas pueden incorporarse sin acceso arbitrario al
shell ni degradación de las políticas existentes.

## Fase 7 — Calidad operativa y seguridad

**Objetivo:** preparar el proyecto para uso continuado por una persona o un equipo.

- [ ] Sustituir capturas amplias por errores específicos y mensajes accionables.
- [ ] Añadir logs estructurados sin secretos.
- [ ] Definir una política de backup y restauración de la base local.
- [ ] Añadir exportación/importación de workspace.
- [ ] Revisar permisos de archivos y directorios creados por `bbai`.
- [ ] Añadir pruebas de regresión para redacción, scope, aprobación y persistencia.
- [ ] Medir tiempos, tamaño de contexto y coste local de las investigaciones.
- [ ] Documentar límites conocidos y modelo de amenazas.

**Criterio de salida:** el proyecto ofrece diagnósticos, recuperación y garantías
operativas suficientes para confiar en él durante una investigación real.

## Dependencias recomendadas

El orden recomendado es:

```text
Migraciones Alembic
  → Findings/revisión
  → Sesiones
  → Reporting
  → Búsqueda
  → Autenticación avanzada
  → Más herramientas
  → Automatización supervisada
  → Frontend
```

La automatización y el frontend deben consumir servicios de dominio y políticas ya
estabilizados; no deben duplicar lógica de seguridad dentro de una capa de presentación
o de un grafo de agentes.

## Propuesta abierta: autonomía supervisada

### Qué problema resolvería

Actualmente el modelo puede proponer una herramienta, pero el flujo es esencialmente
una interacción puntual. Una capa de orquestación permitiría describir un objetivo como:

```text
Enumerar superficie
  → seleccionar una ruta de lectura
  → inspeccionar respuestas
  → registrar evidencias
  → proponer observaciones
  → solicitar revisión humana
```

### Propuesta de diseño

No propondría empezar introduciendo LangGraph directamente. Primero conviene definir un
**motor de workflow propio y pequeño**, persistente y auditable, con:

- estados explícitos (`planned`, `awaiting_approval`, `running`, `paused`,
  `needs_review`, `completed`, `failed`);
- pasos tipados y allowlist de herramientas;
- checkpoints persistidos;
- reanudación después de reinicios;
- aprobación por paso o por lote limitado;
- límites de tiempo, número de pasos, scope y presupuesto de ejecución;
- cancelación inmediata;
- registro de entradas, salidas y decisiones;
- bloqueo automático ante cambios de scope, acciones intrusivas o incertidumbre.

LangGraph podría evaluarse después como implementación del motor si aporta persistencia,
checkpoints y streaming sin obligar a mover las políticas al framework. El grafo nunca
debe tener autoridad para saltarse `ScopePolicy`, la aprobación humana o el registro de
evidencias.

### Niveles de autonomía propuestos

1. **Asistido:** el modelo propone un paso y la persona lo aprueba.
2. **Secuencia supervisada:** la persona aprueba un plan corto; cada herramienta sigue
   teniendo validación y límites.
3. **Ejecución por lotes seguros:** solo pasos de lectura, dentro de scope, con límites
   estrictos y pausa automática ante cualquier anomalía.
4. **No permitido por defecto:** explotación, cambios de estado, login automatizado,
   evasión de controles o acciones fuera de scope.

Esta propuesta queda **pendiente de aprobación** y no forma parte todavía de las fases
comprometidas.

## Propuesta abierta: frontend

### Recomendación

Sí tiene sentido un frontend, pero después de completar findings, sesiones y reporting
en la CLI. Esas piezas definirán el dominio real que la interfaz debe representar.

La opción recomendada para una primera versión sería:

- backend local en Python, reutilizando servicios existentes;
- API HTTP local explícita, por ejemplo FastAPI;
- frontend web local ligero, con TypeScript;
- comunicación en tiempo real mediante SSE o WebSocket para ejecuciones y aprobaciones;
- autenticación local del frontend y escucha limitada a `localhost`;
- la CLI y la UI consumen los mismos casos de uso, sin duplicar reglas.

### Pantallas iniciales

1. Dashboard de targets y sesiones.
2. Vista de investigación con timeline de preguntas, tools, aprobaciones y evidencias.
3. Bandeja de aprobaciones pendientes.
4. Vista de observaciones, hipótesis y findings.
5. Revisión de finding con sus evidencias enlazadas.
6. Exportación y previsualización de informes.
7. Gestión de perfiles de autenticación sin mostrar secretos.

### Riesgos a controlar

- no duplicar la política de scope en JavaScript;
- no exponer la API local a la red por defecto;
- no enviar secretos al navegador si no es imprescindible;
- no convertir el dashboard en una vía de aprobación accidental;
- mantener paridad funcional entre CLI y frontend.

Esta propuesta también queda **pendiente de aprobación** y no se añade aún al plan
comprometido.

## Decisiones que necesitamos tomar antes de las propuestas

1. ¿La autonomía supervisada debe centrarse inicialmente en recon y lectura, excluyendo
   cualquier acción intrusiva?
2. ¿Queremos un frontend web local o preferimos primero una TUI/CLI enriquecida?
3. ¿El producto se orienta primero a un investigador individual o a equipos con
   colaboración y roles?
4. ¿Debe el primer informe estar orientado a Markdown técnico, a formatos de plataformas
   Bug Bounty o a ambos?
