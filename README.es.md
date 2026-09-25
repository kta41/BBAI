# bbai

> **Un espacio de investigación local y bajo control humano para equipos de Bug Bounty y Web Security.**

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

El MVP actual ya incluye el ciclo básico de investigación, tool calling local con
Ollama, validación de scope, cuatro herramientas controladas, registro de ejecuciones,
perfiles HTTP autenticados, redacción de secretos, persistencia de evidencias,
observaciones e hipótesis. El roadmap pendiente se centra en completar findings, flujos
de revisión, informes, sesiones, búsquedas e integraciones más avanzadas.

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
- SQLite
- keyring
- pytest
- Ruff
- mypy

`uv` es opcional. El proyecto también funciona con las herramientas estándar de
empaquetado de Python.

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
```

Para probar tool calling sin ejecutar acciones:

```bash
bbai investigate "Analiza el target" --dry-run
```

## Herramientas y seguridad

Ollama puede proponer cuatro herramientas, siempre con aprobación interactiva y scope
obligatorio:

- `http_inspect`: GET de lectura con respuesta, cabeceras y cuerpo truncado.
- `http_headers`: GET de lectura limitado a cabeceras.
- `subfinder`: enumeración pasiva de subdominios.
- `ffuf`: descubrimiento de contenido acotado a una URL `FUZZ` y una wordlist local.

No existe ejecución arbitraria de shell. Las herramientas externas se ejecutan con
argumentos construidos por la aplicación, sin `shell=True`, con timeout y límite de
salida.

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
bbai auth list
```

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
siendo manuales; la importación de cookies desde navegador y OAuth/SSO quedan para una
fase posterior.

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
- scope policy;
- aprobación humana;
- dry-run;
- registro de ejecuciones;
- perfiles de autenticación;
- keyring;
- redacción de secretos;
- evidencias;
- observaciones;
- hipótesis.

Pendiente:

1. findings completos y revisión humana;
2. sesiones y notas;
3. informes Markdown/JSON;
4. migraciones Alembic;
5. SQLite FTS5 y búsqueda;
6. importación de cookies y OAuth/SSO;
7. comparación entre perfiles de autenticación;
8. nuevas herramientas con políticas específicas.

## Calidad

El proyecto incluye tests con pytest, linting con Ruff y type checking con mypy.
