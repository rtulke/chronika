#!/bin/bash
# Browser History Tool Setup Script
# Creates virtual environment and installs dependencies

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VENV_NAME="venv"
readonly VENV_PATH="${SCRIPT_DIR}/${VENV_NAME}"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi

    local PYTHON_VERSION
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_info "Found Python ${PYTHON_VERSION}"

    # Check if version is >= 3.6
    if ! python3 -c 'import sys; exit(0 if sys.version_info >= (3, 6) else 1)'; then
        log_error "Python 3.6+ required, found ${PYTHON_VERSION}"
        exit 1
    fi
}

create_venv() {
    if [[ -d "${VENV_PATH}" ]]; then
        log_warn "Virtual environment already exists: ${VENV_PATH}"
        read -p "Remove and recreate? (y/N): " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "${VENV_PATH}"
        else
            log_info "Using existing virtual environment"
            return 0
        fi
    fi

    log_info "Creating virtual environment: ${VENV_NAME}"
    python3 -m venv "${VENV_PATH}"
}

install_dependencies() {
    log_info "Activating virtual environment"
    # shellcheck source=/dev/null
    source "${VENV_PATH}/bin/activate"

    log_info "Upgrading pip"
    pip install --upgrade pip

    if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        log_info "Installing dependencies from requirements.txt"
        pip install -r "${SCRIPT_DIR}/requirements.txt"
    else
        log_warn "requirements.txt not found, installing toml manually"
        pip install toml
    fi
}

create_config() {
    local CONFIG_FILE="${SCRIPT_DIR}/config.toml.example"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_info "Creating default configuration"
        python3 "${SCRIPT_DIR}/chronika.py" --init-config
    else
        log_info "Configuration file already exists: ${CONFIG_FILE}"
    fi
}

make_executable() {
    chmod +x "${SCRIPT_DIR}/chronika.py"
    log_info "Made chronika.py executable"
}

create_activation_script() {
    local ACTIVATE_SCRIPT="${SCRIPT_DIR}/activate_env.sh"

    cat > "${ACTIVATE_SCRIPT}" << EOF
#!/bin/bash
# Activation script for browser history tool
source "${VENV_PATH}/bin/activate"
echo "Browser History Tool environment activated"
echo "Usage: python3 chronika.py [options]"
EOF

    chmod +x "${ACTIVATE_SCRIPT}"
    log_info "Created activation script: activate_env.sh"
}

verify_installation() {
    log_info "Verifying installation"

    # shellcheck source=/dev/null
    source "${VENV_PATH}/bin/activate"

    if python3 -c "import toml; print('toml module OK')" 2>/dev/null; then
        log_info "Dependencies verified successfully"
    else
        log_error "Dependency verification failed"
        exit 1
    fi

    if python3 "${SCRIPT_DIR}/chronika.py" --help &>/dev/null; then
        log_info "Tool verification successful"
    else
        log_error "Tool verification failed"
        exit 1
    fi
}

show_usage() {
    cat << EOF

${GREEN}Setup completed successfully!${NC}

To use the browser history tool:

1. Activate the virtual environment:
   ${YELLOW}source ${VENV_NAME}/bin/activate${NC}

   Or use the convenience script:
   ${YELLOW}source activate_env.sh${NC}

2. Run the tool:
   ${YELLOW}python3 chronika.py${NC}

   Examples:
   ${YELLOW}python3 chronika.py --format json${NC}
   ${YELLOW}python3 chronika.py --days 3 --limit 50${NC}

3. View help:
   ${YELLOW}python3 chronika.py --help${NC}

Configuration file: ${YELLOW}browser_history.toml${NC}

EOF
}

main() {
    log_info "Setting up Browser History Tool"

    cd "${SCRIPT_DIR}"

    check_python
    create_venv
    install_dependencies
    create_config
    make_executable
    create_activation_script
    verify_installation

    show_usage

    log_info "Setup completed successfully!"
}

# Run main function
main "$@"
