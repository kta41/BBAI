#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"
BIN_DIR="${HOME}/.local/bin"
BBAI_COMMAND="${BIN_DIR}/bbai"

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "Error: python3 no está instalado o no está disponible en PATH." >&2
    exit 1
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    printf 'Creando entorno virtual en %s\n' "${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
fi

printf '%s\n' "Instalando bbai y sus dependencias..."
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install --editable "${PROJECT_DIR}"

mkdir -p "${BIN_DIR}"
ln -sfn "${VENV_DIR}/bin/bbai" "${BBAI_COMMAND}"

add_path_to_file() {
    local shell_file="$1"
    local marker="# bbai: add local user binaries to PATH"

    touch "${shell_file}"
    if ! grep -Fqx "${marker}" "${shell_file}" 2>/dev/null; then
        {
            printf '\n%s\n' "${marker}"
            printf 'export PATH="$HOME/.local/bin:$PATH"\n'
        } >>"${shell_file}"
    fi
}

add_path_to_file "${HOME}/.profile"
[[ -f "${HOME}/.bashrc" ]] && add_path_to_file "${HOME}/.bashrc"
[[ -f "${HOME}/.zshrc" ]] && add_path_to_file "${HOME}/.zshrc"

export PATH="${BIN_DIR}:${PATH}"

printf '\n%s\n' "bbai quedó instalado correctamente."
printf 'Ejecutable: %s\n' "${BBAI_COMMAND}"
printf '%s\n' "En una terminal nueva ya podrás ejecutar: bbai --help"
printf '%s\n' "Para activar PATH inmediatamente en esta terminal: source ~/.profile"
printf '%s\n' "Después, inicializa un workspace con: bbai init"
