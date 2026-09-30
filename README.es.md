# bbai

> **Un espacio de investigación local y bajo control humano para equipos de Bug Bounty y Web Security.**
>
> **Estado: alpha.** El proyecto sigue evolucionando; las integraciones y sus garantías pueden cambiar.

La investigación de seguridad suele estar repartida entre terminales, pestañas del
navegador, notas, clientes HTTP, resultados de scanners y conversaciones aisladas con
IA. `bbai` reúne ese flujo en un único producto local: ofrece un workspace persistente
para targets, scope, evidencias, ejecuciones de herramientas, observaciones, hipótesis y
findings, utilizando modelos locales de Ollama para acelerar el análisis sin enviar datos
sensibles de investigación a servicios de IA hospedados.

`bbai` está pensado para investigadores y equipos de seguridad que necesitan:

- pasar de una pregunta inicial a una investigación respaldada por evidencias más rápido;
- conservar el contexto y las decisiones entre sesiones y entregas de trabajo;
- utilizar la IA como multiplicador de productividad manteniendo bajo control humano toda
  acción relevante;
- trabajar con targets autenticados sin exponer credenciales al modelo ni a la base de datos;
- mantener una trazabilidad fiable desde la ejecución de una herramienta hasta la
  evidencia, hipótesis, finding e informe.

El producto es local-first, extensible y deliberadamente conservador: el modelo puede
proponer una herramienta autorizada, pero `bbai` valida el scope, solicita aprobación
humana, aplica límites de ejecución, redacta secretos y almacena el resultado para su
revisión. No es un agente autónomo de explotación y nunca proporciona acceso arbitrario
al shell para el LLM.

[Read this README in English](README.md).

Usa `bbai` y sus herramientas únicamente en sistemas propios o para los que tengas
autorización explícita. Las comprobaciones de scope y las confirmaciones son salvaguardas,
no sustituyen la autorización ni garantizan que se impida toda acción insegura.
`gau`, `katana`, `nuclei` y las demás integraciones externas son herramientas separadas:
verifica su comportamiento, versión, términos y las reglas del programa antes de usarlas.
Las integraciones se han probado con mocks, no contra targets reales. Consulta
[SECURITY.md](SECURITY.md) para reportar vulnerabilidades de forma responsable.

## Visión de producto

El objetivo a largo plazo es evolucionar desde un workspace local asistido por IA hacia
una plataforma controlada de investigación de seguridad:

```text
Pregunta
  → Contexto
  → Llamada a herramienta aprobada
  → Política de scope y seguridad
  → Evidencia
  → Observación
  → Hipótesis
  → Finding revisado por una persona
  → Informe
```

El MVP actual incluye el ciclo de investigación, tool calling local con Ollama,
validación de scope, siete herramientas controladas, perfiles HTTP autenticados,
redacción de secretos, evidencias, observaciones e hipótesis, findings revisables,
sesiones persistidas, informes Markdown/JSON, búsqueda SQLite FTS5 y diagnóstico del
workspace. El roadmap pendiente se centra en autenticación avanzada, más integraciones y
hardening operativo.

Consulta el plan detallado en [ROADMAP.md](ROADMAP.md).

## Objetivos

- Mantener un workspace local para targets, evidencias, notas, findings e informes.
- Utilizar modelos locales mediante Ollama en `http://localhost:11434` por defecto.
- Separar CLI, dominio, construcción de contexto, almacenamiento y proveedores LLM.
- Mantener una arquitectura extensible para RAG, tool calling y automatización controlada.

## Arquitectura

- **CLI:** capa de interacción (`bbai ...`).
- **Core:** modelos y servicios de dominio.
- **LLM:** abstracción de proveedor (`LLMProvider` / `OllamaProvider`).
- **Context:** construcción de prompts con contexto persistido.
- **Storage:** SQLite + SQLAlchemy para persistencia local.
- **Tools:** integraciones de seguridad con scope, límites y aprobación.
- **Auth:** perfiles por target, keyring del sistema y redacción de secretos.

## Stack

- Python 3.12+
- Typer
- Pydantic
- HTTPX
- SQLAlchemy
- Alembic para migraciones SQLite versionadas
- SQLite
- keyring
- pytest
- Ruff
- mypy

`uv` es opcional. El proyecto también funciona con las herramientas estándar de
empaquetado de Python.

## Licencia

Publicado bajo la [licencia MIT](LICENSE).

## Inicio rápido

Instala el comando persistente una sola vez:

```bash
./setup.sh
source ~/.profile
bbai --help
bbai init
```

El instalador crea `.venv`, instala el proyecto en modo editable y crea
`~/.local/bin/bbai`. Tras reiniciar el equipo, bastará con abrir una terminal y utilizar
`bbai <comando>`.

La primera vez que ejecutes `bbai init`, un asistente te permitirá instalar todas,
algunas o ninguna de las herramientas opcionales (`subfinder`, `ffuf`, `gau`, `katana` y
`nuclei`); para ellas hace falta Go. También podrás elegir instalar Ollama con su
instalador oficial y descargar el modelo configurado (`llama3.1` por defecto; puede
ocupar varios GB). No se instala nada externo sin que lo selecciones. Puedes volver a
abrir el asistente con `bbai init --setup`, omitirlo con
`bbai init --skip-dependency-setup` y revisar dependencias con `bbai doctor`.

Instalación manual:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
bbai init
bbai target add example.com --description "Aplicación web pública" --scope "example.com"
```

## Flujo de uso

```bash
bbai init
bbai target add example.com --scope "*.example.com"
bbai target use example.com
bbai status
bbai tool list
bbai tool check
bbai investigate "Comprueba la página principal y resume las cabeceras relevantes"
bbai evidence list
bbai observation list
bbai hypothesis list
bbai tool executions
bbai doctor
bbai search "cabeceras de seguridad" --type evidence
```

Para probar tool calling sin ejecutar acciones:

```bash
bbai investigate "Analiza el target" --dry-run
```

## Findings, sesiones e informes

Cada `investigate` crea una sesión activa si no hay una seleccionada. Las preguntas,
respuestas, llamadas a herramientas y resultados quedan en el historial local:

```bash
bbai session list
bbai session show
bbai session note "Revisar el comportamiento con una cuenta de bajo privilegio"
bbai session pause
bbai session resume 1
bbai session close
bbai session labels 1 --label auth --label triage
bbai session export 1 --output session.json
bbai session prune --older-than-days 90
bbai session prune --older-than-days 90 --apply
```

La retención es una vista previa por defecto y solo permite eliminar sesiones cerradas
o pausadas; conserva sus evidencias y demás artefactos de investigación.

Los findings comienzan como borradores y solo pueden aceptarse o rechazarse mediante
revisión humana:

```bash
bbai finding create "Exposición de debug" "Se devuelven metadatos internos" --severity medium --evidence 1
bbai finding update 1 --status in_review
bbai finding review 1 --decision accepted --note "Reproducido dos veces"
bbai finding show 1
bbai report 1 --format markdown --output informe.md
bbai report --format json --output informe.json
```

Los informes Markdown admiten plantillas locales con placeholders como `$title`,
`$target` y `$summary`, mediante `bbai report --template plantilla.md`.

Por defecto, los informes incluyen únicamente findings aceptados o reportados.
`--include-drafts` permite exportar explícitamente estados no aceptados. Antes de
mostrar o escribir el informe se redactan secretos de los perfiles activos del keyring.

## Backup y restauración

`bbai backup` crea una copia consistente de la base SQLite en `.bbai/backups/`; se
puede indicar otra ruta con `--output`. Para restaurarla:

```bash
bbai backup --output ./bbai-backup.db
bbai restore ./bbai-backup.db
bbai restore ./bbai-backup.db --replace
```

La restauración no sobrescribe una base existente a menos que se indique `--replace`.
En ese caso, la base actual se conserva junto a ella con el sufijo
`.pre-restore-<n>.bak`. Los backups contienen la base de investigación, pero no
`.bbai.toml` ni las credenciales guardadas en el keyring. Trátalos como datos sensibles
y evita subirlos al repositorio.

## Herramientas y seguridad

Ollama puede proponer siete herramientas, siempre con aprobación interactiva y scope
obligatorio:

- `http_inspect`: GET de lectura con respuesta, cabeceras y cuerpo truncado.
- `http_headers`: GET de lectura limitado a cabeceras.
- `subfinder`: enumeración pasiva de subdominios.
- `ffuf`: descubrimiento de contenido acotado a una URL `FUZZ` y una wordlist local.
- `gau`: recopilación pasiva de URLs archivadas, filtradas por el scope aprobado.
- `katana`: crawl limitado al hostname inicial y al scope aprobado.
- `nuclei`: solo ejecuta dos comprobaciones locales de bajo impacto para cabeceras HTTP;
  el modelo no puede elegir plantillas ni límites.

`bbai tool list` muestra la clasificación, riesgo, permiso, aprobación requerida y límites
de timeout/salida de cada integración. El scope por hostname autoriza HTTP/HTTPS en los
puertos estándar 80 y 443; para un puerto no estándar debe añadirse explícitamente, por
ejemplo `example.com:8443` o `*.example.com:8443`. Para IPv6 con puerto se usa
`[2001:db8::1]:8443`. Las URLs con credenciales embebidas se rechazan. `http_inspect` no
sigue redirecciones y `katana`/`nuclei` se ejecutan con el seguimiento de redirecciones
deshabilitado.

No existe ejecución arbitraria de shell. Las herramientas externas se ejecutan con
argumentos construidos por la aplicación, sin `shell=True`, con timeout y límite de
salida.
En POSIX, `.bbai/` se mantiene con permisos `0700`, y la base, configuración, backups,
informes y `audit.jsonl` con `0600`. El audit log es JSONL y solo registra herramienta,
estado, aprobación y duración; no incluye target, argumentos, salida ni credenciales.
No es un registro inviolable: un usuario con acceso al workspace puede modificarlo.

`bbai doctor` revisa el workspace, SQLite/migraciones/FTS5, Ollama y el modelo
configurado, la disponibilidad del keyring, el target activo y los binarios opcionales. Las advertencias
señalan dependencias opcionales o configuración ausente; un error de base de
datos/diagnóstico devuelve un código distinto de cero. `bbai search` consulta el índice
local FTS5 de targets, evidencias, observaciones, hipótesis, findings, notas y eventos
de sesión. Se puede filtrar con `--target`, `--session`, `--type`, `--status` y
`--severity`, o reconstruirlo con `--rebuild`.
`bbai search --semantic` ofrece ranking experimental con embeddings locales de Ollama.
`bbai search-evaluate dataset.json --strategy fts` (o `semantic`) calcula precision@k,
recall@k, reciprocal rank y latencia sobre un dataset JSON de consultas etiquetadas.
`bbai metrics` resume tamaño de contexto y duración de ejecuciones; Ollama no persiste
uso de tokens/coste, por lo que ese dato no se estima.

Se pueden importar resultados estructurados de Nuclei JSONL y SARIF como findings en
borrador: `bbai import-results salida.jsonl --format nuclei-jsonl`. Los resultados con
ubicaciones URL fuera del scope configurado se descartan. Para mover la base de
investigación entre workspaces usa `bbai workspace export portable.bbai.zip` y
`bbai workspace import portable.bbai.zip`; importar sobre una base existente requiere
`--replace` y crea primero un backup. El archivo portable excluye `.bbai.toml` y los
secretos del keyring.

## Evidencias, observaciones e hipótesis

```bash
bbai evidence add ./request.txt --kind http-request
bbai evidence list

bbai observation add \
  "La respuesta expone un header de debug" \
  --evidence 1

bbai hypothesis add \
  "La información de debug podría estar disponible sin autenticación" \
  --observation 1 \
  --confidence medium

bbai hypothesis update 1 --status supported
```

La aplicación distingue entre:

- **evidencia:** dato crudo;
- **observación:** interpretación técnica;
- **hipótesis:** explicación pendiente de validar;
- **finding:** resultado potencialmente reportable.

Las observaciones e hipótesis se incorporan al contexto de `bbai ask` e `bbai
investigate`. El modelo no convierte automáticamente cualquier respuesta en un finding.

## Autenticación

Los targets pueden tener perfiles separados:

```bash
bbai auth profile-add normal-user --type cookie
bbai auth profile-add api-client --type bearer
bbai auth profile-add partner --type api_key
bbai auth profile-add custom --type headers
bbai auth profile-add anon --role anonymous --expires-in-hours 8
bbai auth list
```

La expiración también puede definirse con `--expires-at` (ISO-8601 con zona horaria).
Para importar cookies desde un archivo se requiere confirmación explícita:
`bbai auth cookie-import normal-user cookies.txt --role user`. Para comparar dos perfiles
se hacen dos GET de solo lectura a una URL en scope, cada uno con aprobación humana:
`bbai auth compare --url https://example.com/account --left anon --right normal-user`.
Se comparan estado HTTP, tipo de contenido y hash del cuerpo, sin guardar el cuerpo.

Para utilizar un perfil:

```bash
bbai investigate \
  "Comprueba /api/profile usando la sesión del usuario normal" \
  --auth normal-user
```

Los secretos se almacenan en el keyring del sistema. SQLite solo guarda metadatos y una
referencia al secreto. Los valores se inyectan en memoria, se redactan antes de guardar
evidencias o enviarlos a Ollama, y pueden revocarse:

```bash
bbai auth revoke normal-user
```

Esta versión soporta `bearer`, `cookie`, `api_key` y `headers`. El login y MFA siguen
siendo manuales; OAuth/SSO y refresh tokens quedan para una fase posterior. Los perfiles también se aplican a `ffuf` mediante headers y sus valores
se redactan en la salida persistida. Los perfiles también se aplican a `katana` y
`nuclei` mediante headers. `gau` los usa solo para redactar valores y no envía
credenciales al servicio de archivos históricos.

## Principios

- Human-in-the-loop por defecto.
- Ejecución local y protección frente a exfiltración de secretos.
- Scope validado antes de ejecutar herramientas.
- No hay acceso arbitrario al shell para el LLM.
- Persistencia de evidencias y ejecuciones.
- Findings siempre revisables por una persona.
- Arquitectura modular y extensible.

## Estado actual y roadmap

Ya están integrados:

- instalación persistente;
- targets y target activo;
- SQLite y SQLAlchemy;
- integración básica con Ollama;
- tool calling;
- `http_inspect`, `http_headers`, `subfinder` y `ffuf`;
- `gau`, `katana` y `nuclei` con scope, límites y registro de ejecuciones;
- scope policy;
- aprobación humana;
- dry-run;
- registro de ejecuciones;
- perfiles de autenticación;
- keyring;
- redacción de secretos;
- evidencias;
- observaciones;
- hipótesis;
- findings con flujo de revisión humana;
- sesiones persistidas y reanudables;
- informes Markdown/JSON;
- etiquetas, retención y exportación de sesiones;
- plantillas Markdown para informes;
- migraciones Alembic con adopción de workspaces existentes;
- autenticación de `ffuf` con redacción de secretos;
- búsqueda SQLite FTS5 y comando `bbai search`;
- ranking semántico experimental y evaluación comparativa de búsqueda;
- importación de resultados Nuclei JSONL y SARIF;
- exportación/importación portable del workspace y métricas locales;
- diagnóstico `bbai doctor`.

Pendiente de decisión/propuesta:

1. OAuth/SSO, refresh tokens y un almacén cifrado opt-in;
2. autonomía supervisada y frontend;
3. RAG/contexto semántico persistente y medición de coste LLM.

Findings/revisión, sesiones persistidas, informes Markdown/JSON, migraciones Alembic y
autenticación de `ffuf` ya están implementados. El detalle de tareas y criterios de salida
está en [ROADMAP.md](ROADMAP.md).

## Calidad

El proyecto incluye tests con pytest, linting con Ruff y type checking con mypy.
