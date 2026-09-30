# bbai

> **A local, human-controlled investigation workspace for Bug Bounty and Web Security teams.**
>
> **Status: alpha.** This project is evolving; integrations and safety behavior may change.

Security research is often spread across terminals, browser tabs, notes, HTTP clients,
scanner output, and disconnected AI conversations. `bbai` brings that workflow into one
local product: it gives researchers a persistent workspace for targets, scope, evidence,
tool executions, observations, hypotheses, and findings, while using local Ollama models
to accelerate analysis without sending sensitive research data to a hosted AI service.

`bbai` is designed for researchers and security teams that need to:

- move from an initial question to evidence-backed investigation faster;
- preserve context and decisions across sessions and team handoffs;
- use AI as a force multiplier while keeping every impactful action under human control;
- work with authenticated targets without exposing credentials to the model or database;
- create a reliable trail from tool execution to evidence, hypothesis, finding, and report.

The product is local-first, extensible, and deliberately conservative: the model can
propose an approved tool, but `bbai` validates scope, requests human approval, applies
execution limits, redacts secrets, and stores the result for review. It is not an
autonomous exploitation agent and it never provides arbitrary shell access to the LLM.

[Read this README in Spanish](README.es.md).

Use `bbai` and its tools only against systems you own or are explicitly authorized to
assess. Scope checks and approval prompts are safeguards, not a substitute for
authorization or a guarantee that every unsafe action is prevented. The `gau`, `katana`,
`nuclei`, and other external integrations are separate tools; verify their behavior,
versions, terms, and target-program rules before use. The integrations have been tested
with mocks, not validated against live targets. See [SECURITY.md](SECURITY.md) for
responsible disclosure and reporting instructions.

## Product vision

The long-term goal is to evolve from a local AI-assisted investigation workspace into a
controlled security research platform:

```text
Question
  → Context
  → Approved tool call
  → Scope and safety policy
  → Evidence
  → Observation
  → Hypothesis
  → Human-reviewed finding
  → Report
```

The MVP includes the core investigation loop, local Ollama tool calling, scope validation,
seven controlled tools, authenticated HTTP profiles, redaction, evidence, observations,
hypotheses, reviewed findings, resumable investigation sessions, Markdown/JSON reporting,
SQLite FTS5 search, and workspace diagnostics. The remaining roadmap focuses on advanced
authentication, additional integrations, and operational hardening.

See the detailed plan in [ROADMAP.md](ROADMAP.md).

## Goals

- Keep a local workspace for targets, evidence, notes, findings, and reports.
- Use local LLMs through Ollama at `http://localhost:11434` by default.
- Separate CLI, domain logic, context building, storage, and provider abstraction.
- Keep the architecture extensible for future RAG, tool calling, and security workflow automation.

## Architecture overview

- CLI: interactive command layer (`bbai ...`)
- Core: domain models and services
- LLM: provider abstraction (`LLMProvider` / `OllamaProvider`)
- Context: structured prompt building for evidence-aware analysis
- Storage: SQLite + SQLAlchemy for local persistence
- Tools: abstraction for security utilities and future integrations

## Recommended stack

This project uses:

- Python 3.12+
- Typer for CLI commands
- Pydantic for configuration and validation
- HTTPX for HTTP client communication
- SQLAlchemy for local SQLite persistence
- Alembic for versioned SQLite migrations
- pytest for tests
- Ruff for linting
- mypy for static typing

`uv` is a good optional tool for project management when available, but the project is intentionally compatible with standard Python packaging tools. This keeps setup reliable in environments where `uv` is not installed yet.

## License

Released under the [MIT License](LICENSE).

## Quick start

La forma recomendada de instalar el comando persistente es ejecutar el instalador una sola vez:

```bash
./setup.sh
source ~/.profile
bbai --help
```

El instalador crea `.venv`, instala el proyecto en modo editable y crea el ejecutable
`~/.local/bin/bbai`. También añade `~/.local/bin` al `PATH` persistente del usuario.
Después de reiniciar el equipo solo será necesario abrir una terminal y usar `bbai <comando>`.
Para inicializar el workspace actual:

```bash
bbai init
```

La primera vez, `bbai init` ofrece un asistente interactivo para instalar todas, algunas
o ninguna de las herramientas opcionales (`subfinder`, `ffuf`, `gau`, `katana` y
`nuclei`). La instalación de estas herramientas requiere Go. También puede ofrecer
instalar Ollama mediante su instalador oficial y descargar el modelo configurado
(`llama3.1` por defecto; descarga grande). Cada instalación o descarga requiere elegirla
explícitamente. Para repetir el asistente usa `bbai init --setup`; para omitirlo,
`bbai init --skip-dependency-setup`. La instalación se puede completar más tarde, y
`bbai doctor` muestra qué dependencias siguen faltando.

Si `~/.local/bin` ya estaba en el `PATH`, el `source` no será necesario. También se puede
cargar el instalador en la shell actual con `source ./setup.sh`.

### Instalación manual

Si se prefiere no usar el instalador:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
bbai init
bbai target add example.com --description "Example target" --scope "example.com"
```

## Example commands

```bash
bbai init
bbai target add example.com --description "Public web app" --scope "*.example.com"
bbai target use example.com
bbai status
bbai evidence add ./evidence/request.txt --kind http-request
bbai evidence list
bbai ask "¿Qué sabemos hasta ahora sobre este target?"
bbai investigate "Comprueba la página principal y resume las cabeceras relevantes"
bbai investigate "Analiza el target" --dry-run
bbai session list
bbai tool list
bbai tool check
bbai tool executions
bbai observation list
bbai hypothesis list
bbai analyze ./evidence/request.txt
bbai finding list
bbai finding create "Debug disclosure" "The response exposes debug metadata" --severity medium --evidence 1
bbai finding update 1 --status in_review
bbai finding review 1 --decision accepted --note "Verified manually"
bbai report 1 --format markdown --output report.md
bbai doctor
bbai search "security headers" --type evidence
```

El target activo se guarda en `.bbai.toml`, por lo que se mantiene entre sesiones y
reinicios. Se puede sobrescribir puntualmente con `--target`.

`bbai investigate --dry-run` permite revisar qué herramientas propone Ollama sin ejecutar
ninguna acción. Cada intento se registra como ejecución con estado `dry_run`, `denied`,
`failed` o `succeeded`:

```bash
bbai tool executions
```

## Findings, sesiones e informes

Cada `investigate` crea una sesión activa si no hay ninguna seleccionada. La pregunta,
respuesta, llamadas a herramientas y resultados quedan en el historial local:

```bash
bbai session list
bbai session show
bbai session note "Revisar comportamiento con una cuenta de bajo privilegio"
bbai session pause
bbai session resume 1
bbai session close
```

Los findings empiezan como borradores y solo se pueden aceptar o rechazar desde el flujo
de revisión humana:

```bash
bbai finding create "Debug disclosure" "Internal metadata is returned" --severity medium --evidence 1
bbai finding update 1 --status in_review
bbai finding review 1 --decision accepted --note "Reproduced twice"
bbai finding show 1
bbai report 1 --format markdown --output report.md
bbai report --format json --output report.json
```

Los informes incluyen solo findings aceptados/reportados de forma predeterminada.
`--include-drafts` permite exportar explícitamente estados no aceptados; los secretos
almacenados en los perfiles activos del keyring se redactan antes de mostrar o escribir
el informe.

## Evidencias

Las evidencias se almacenan en SQLite y se incorporan automáticamente al contexto de
`bbai ask` cuando existe un target activo:

```bash
bbai evidence add ./request.txt --kind http-request
bbai evidence add ./response.txt --kind http-response
bbai evidence list
```

La aplicación solo lee y persiste los ficheros indicados; no ejecuta contenido de
evidencias ni permite que el modelo ejecute comandos.

## Observations and hypotheses

La fase 2 separa el dato crudo de su interpretación:

```bash
bbai observation add "La respuesta expone un header de debug" --evidence 1
bbai observation list

bbai hypothesis add \
  "La información de debug podría estar disponible sin autenticación" \
  --observation 1 \
  --confidence medium
bbai hypothesis list
bbai hypothesis update 1 --status supported
```

Las observaciones y las hipótesis se incorporan al contexto de `bbai ask` e
`bbai investigate`. Crear una observación o hipótesis es siempre una acción
explícita del investigador; el modelo no convierte automáticamente cualquier
respuesta en un finding.

## Autenticación de targets

Los targets pueden tener perfiles de autenticación separados. Los secretos se almacenan
en el keyring del sistema mediante `keyring`; SQLite solo conserva metadatos y una
referencia al secreto:

```bash
bbai auth profile-add normal-user --type cookie
bbai auth profile-add api-client --type bearer
bbai auth profile-add partner --type api_key
bbai auth profile-add custom --type headers
bbai auth list
```

Los valores se solicitan ocultos y no se imprimen. Para usar un perfil en el agente:

```bash
bbai investigate \
  "Comprueba /api/profile usando la sesión del usuario normal" \
  --auth normal-user
```

La confirmación indica el perfil y el tipo de autenticación, pero nunca muestra el
secreto. Los valores se inyectan solo en memoria, se redactan antes de guardar evidencias
o enviarlas a Ollama, y el perfil puede revocarse:

```bash
bbai auth revoke normal-user
```

Esta primera versión soporta `bearer`, `cookie`, `api_key` y `headers`. La importación
de cookies exportadas desde un navegador y los flujos OAuth/SSO se añadirán después; el
login y MFA siguen siendo manuales. Los perfiles se aplican también a `ffuf`, `katana` y
`nuclei` mediante headers; `gau` solo los usa para redactar valores, sin enviar
credenciales al servicio de archivos históricos. Sus valores se eliminan de las salidas
persistidas.

## Tool calling experimental

El MVP incluye un primer flujo de tool calling mediante `bbai investigate`. Ollama puede
proponer siete herramientas, siempre con aprobación interactiva y scope obligatorio:

- `http_inspect`: GET de lectura con respuesta, cabeceras y cuerpo truncado.
- `http_headers`: GET de lectura limitado a cabeceras.
- `subfinder`: enumeración pasiva de subdominios mediante el binario instalado.
- `ffuf`: descubrimiento de contenido acotado a una URL `FUZZ` y una wordlist local.
- `gau`: recopilación pasiva de URLs archivadas, filtradas por el scope aprobado.
- `katana`: crawl limitado al hostname inicial y al scope aprobado.
- `nuclei`: solo ejecuta dos comprobaciones locales de bajo impacto para cabeceras HTTP;
  el modelo no puede elegir plantillas ni límites.

```bash
bbai target use example.com
bbai investigate "Comprueba https://example.com/ y resume la respuesta"
```

Cada ejecución autorizada se almacena como evidencia `tool-<nombre>`. No existe
ejecución de shell arbitraria ni peticiones fuera de scope. Las herramientas externas se
ejecutan con argumentos construidos por la aplicación, sin `shell=True`, con timeout y
límite de salida. El modelo propone la herramienta, pero la aplicación valida el nombre,
los argumentos, el protocolo, el scope y la aprobación humana antes de ejecutarla. `subfinder`,
`ffuf`, `gau`, `katana` y `nuclei` deben estar instalados por el usuario y disponibles en
`PATH`.

`bbai doctor` revisa el workspace, SQLite/migraciones/FTS5, Ollama y el modelo configurado,
el keyring, el target activo y los binarios opcionales. Las advertencias señalan
dependencias opcionales o configuración ausente; un error de base de datos/diagnóstico
devuelve un código de salida distinto de cero. `bbai search` consulta el índice local
FTS5 de targets, evidencias, observaciones, hipótesis, findings, notas y eventos de
sesión. Usa `--target`, `--session`, `--type`, `--status` y `--severity` para acotar la
búsqueda, o `--rebuild` para recrear el índice.

## Design principles

- Human-in-the-loop by default.
- Safe, local-first execution with no secret exfiltration.
- Modular services instead of business logic inside the CLI.
- Persistence-first workflow for evidence and findings.
- Extensible provider layer for future model backends.

## Current status

This is an operational local-first MVP, not an autonomous exploitation agent. Tool
execution remains scoped, bounded, auditable, and subject to human approval. See
[ROADMAP.md](ROADMAP.md) for advanced authentication, supervised workflows, frontend,
backup/restore, and further hardening.
