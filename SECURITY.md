# Security Policy

## Supported versions

Security fixes are currently handled for the latest code on the default branch.
This project is in alpha and does not yet promise maintenance for older releases.

## Responsible use

Use `bbai` and its integrations only on systems you own or are explicitly
authorized to assess. Confirm the target and permitted scope with the system
owner before running any active tool. Follow the target program's rules and the
terms of service of third-party tools and services.

Do not use this project to access, alter, disrupt, or exfiltrate data without
authorization. Do not include real credentials, personal data, or sensitive
target data in public issues, pull requests, or demonstration material.

## Reporting a vulnerability

Please do not report suspected vulnerabilities in a public GitHub issue.

Please reach out directly via email at `kta41@proton.me` without including
vulnerability details or sensitive data in a public issue.

Include, when safe to do so:

- the affected version, commit, and environment;
- a concise description and impact;
- minimal, reproducible steps or a proof of concept that does not access real
  third-party systems or data;
- any suggested mitigation.

The maintainers will coordinate a fix and disclosure with the reporter. Please
allow time for investigation and a fix before publishing details.

## Scope and limitations

`bbai` is alpha software. Its scope checks, approval prompts, and output
redaction are safeguards, not a guarantee that an assessment is authorized or
that every unsafe action is prevented. Third-party tools installed through the
setup wizard are separate projects with their own security policies, behavior,
and licenses. Verify their options and use them only within authorized scope.

## Threat model and operational boundaries

### Assets and trust boundaries

- The SQLite workspace contains targets, scope, evidence, session history, and
  findings. Treat the database and its backups as sensitive assessment data.
- `.bbai.toml` contains workspace and model endpoint configuration. Authentication
  secrets are stored separately in the operating system keyring when a usable
  keyring is available.
- Reports may contain sensitive evidence even after known authentication secrets
  are redacted. Review a report before sharing it.
- The optional local JSONL audit log records only tool name, status, approval, and
  elapsed time. It intentionally omits target names, arguments, tool output, and
  credentials. It is not tamper-evident and is not a substitute for the database
  execution history.
- Ollama, DNS, network services, and third-party command-line tools are outside
  the application's trust boundary. Data sent to a configured model endpoint is
  subject to that endpoint's behavior and configuration.

### Local filesystem protection

On POSIX systems, bbai creates its data directory with mode `0700` and writes the
configuration, SQLite database, generated reports, backups, and audit log with
mode `0600`. These permissions reduce access by other local accounts; they do not
protect data from the current user, root, compromised processes running as that
user, filesystem snapshots, or backups copied elsewhere. Filesystem encryption
and secure backup retention remain the operator's responsibility.

Authentication secrets are not included in SQLite backups. Restoring a workspace
does not restore the keyring entries it references.

### Network and tool limitations

Scope validation is hostname- and port-based. It does not pin DNS answers or
prevent a permitted hostname from resolving to loopback, link-local, private, or
otherwise unexpected addresses. Operators must review DNS and network routing
for their environment. HTTP inspection does not follow redirects; Katana and
Nuclei are configured to disable redirect following, but installed external tool
versions and behaviors should still be verified.

Human approval confirms an individual proposed tool call; it does not verify
ownership or authorization. External tools may generate traffic beyond what their
names imply, and their execution is limited by their own implementation as well
as bbai's configured timeouts and output caps.

### Logging and failure handling

The structured audit log is local operational metadata, not a security event
monitor or immutable audit trail. If it cannot be written after a tool execution,
bbai reports the failure; the execution itself may already have happened and its
database record may already exist. The operator should inspect the workspace
before continuing.

## Política en español

### Versiones con soporte

Por ahora, las correcciones de seguridad se aplican a la última versión del branch
predeterminado. Al estar en alpha, no se garantiza mantenimiento de versiones anteriores.

### Uso responsable

Usa `bbai` y sus integraciones únicamente en sistemas propios o para los que tengas
autorización explícita. Confirma con el propietario el target y el scope permitido antes
de ejecutar herramientas activas. Respeta las reglas del programa y las condiciones de
uso de las herramientas y servicios de terceros.

No accedas, alteres, interrumpas ni extraigas datos sin autorización. No publiques
credenciales reales, datos personales ni información sensible de targets en issues,
pull requests o ejemplos.

### Reportar una vulnerabilidad

No publiques vulnerabilidades sospechadas en un issue público. Contacta directamente
por correo electrónico en `kta41@proton.me`, sin incluir detalles de la vulnerabilidad
ni datos sensibles en un issue público.

Cuando sea seguro, incluye la versión/commit y entorno afectados, una descripción breve
del impacto, pasos mínimos reproducibles que no accedan a sistemas o datos de terceros y
una mitigación sugerida. Coordina la divulgación con los mantenedores y da tiempo para
investigar y corregir antes de publicar los detalles.

### Alcance y limitaciones

`bbai` está en alpha. El control de scope, las confirmaciones y la redacción son
salvaguardas, no sustituyen la autorización ni garantizan que se evite toda acción
insegura. Las herramientas externas son proyectos separados con políticas, comportamiento
y licencias propias; verifica su funcionamiento y úsalas solo dentro del scope autorizado.

### Modelo de amenazas y límites operativos

- SQLite guarda targets, scope, evidencias, historial de sesión y findings. La base y
  sus backups deben tratarse como datos sensibles.
- `.bbai.toml` guarda configuración del workspace y endpoint del modelo. Cuando el
  sistema dispone de un keyring utilizable, las credenciales se guardan allí, separadas
  de SQLite.
- Los informes pueden incluir evidencias sensibles incluso después de redactar secretos
  conocidos; revísalos antes de compartirlos.
- El audit log JSONL registra solo herramienta, estado, aprobación y duración; omite
  nombres de target, argumentos, salida y credenciales. No es inmutable ni reemplaza el
  historial de ejecuciones en la base de datos.
- Ollama, DNS, la red y las herramientas externas están fuera de la frontera de confianza
  de la aplicación. El tratamiento de datos enviados al endpoint configurado depende de
  ese endpoint.

En POSIX, bbai crea el directorio de datos con modo `0700` y escribe configuración,
SQLite, informes, backups y audit log con modo `0600`. Esto reduce el acceso de otras
cuentas locales, pero no protege frente al usuario actual, root, procesos comprometidos
con la misma cuenta, snapshots ni copias trasladadas a otros sistemas. El cifrado del
filesystem y la retención segura de backups son responsabilidad de quien opera el
workspace. Los backups de SQLite no incluyen secretos del keyring; restaurar la base no
restaura las credenciales referenciadas.

La validación de scope se basa en hostname y puerto: no fija las respuestas DNS ni
impide que un hostname permitido resuelva a loopback, redes privadas, link-local u otras
direcciones inesperadas. Revisa DNS y el enrutamiento de tu entorno. `http_inspect` no
sigue redirecciones; Katana y Nuclei se configuran para no seguirlas, pero se deben
verificar también las versiones instaladas y el comportamiento de esas herramientas.

La aprobación humana valida una llamada propuesta, no la propiedad ni la autorización
del target. Las herramientas externas pueden generar tráfico según su propia
implementación y configuración, además de los límites de timeout y salida de bbai. El
audit log es metadato operativo local, no monitor de seguridad ni registro inalterable.
Si falla su escritura tras ejecutar una herramienta, la ejecución pudo ocurrir y quedar
registrada en SQLite; inspecciona el workspace antes de continuar.
