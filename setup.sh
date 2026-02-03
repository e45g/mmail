#!/bin/bash
set -e

# mmail setup script - works across Linux distributions
# Supports: Debian/Ubuntu/Raspberry Pi OS, Fedora/RHEL/CentOS, Arch Linux, Alpine

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=$ID_LIKE
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    elif [ -f /etc/alpine-release ]; then
        DISTRO="alpine"
    else
        DISTRO="unknown"
    fi

    info "Detected distribution: $DISTRO"
}

install_deps() {
    case "$DISTRO" in
        debian|ubuntu|raspbian|linuxmint|pop)
            info "Using apt package manager"
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                gcc \
                make \
                pkg-config \
                libpq-dev \
                libssl-dev \
                postgresql \
                postgresql-contrib
            ;;
        fedora)
            info "Using dnf package manager"
            sudo dnf install -y \
                gcc \
                make \
                pkgconf-pkg-config \
                libpq-devel \
                openssl-devel \
                postgresql-server \
                postgresql-contrib
            ;;
        centos|rhel|rocky|almalinux)
            info "Using yum/dnf package manager"
            if command -v dnf &> /dev/null; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi
            sudo $PKG_MGR install -y \
                gcc \
                make \
                pkgconfig \
                postgresql-devel \
                openssl-devel \
                postgresql-server \
                postgresql-contrib
            ;;
        arch|manjaro|endeavouros)
            info "Using pacman package manager"
            sudo pacman -Sy --noconfirm \
                base-devel \
                gcc \
                make \
                pkgconf \
                postgresql-libs \
                openssl \
                postgresql
            ;;
        alpine)
            info "Using apk package manager"
            sudo apk add --no-cache \
                build-base \
                gcc \
                make \
                pkgconf \
                postgresql-dev \
                openssl-dev \
                postgresql \
                musl-dev \
                linux-headers
            ;;
        *)
            if [[ "$DISTRO_LIKE" == *"debian"* ]] || [[ "$DISTRO_LIKE" == *"ubuntu"* ]]; then
                DISTRO="debian"
                install_deps
                return
            elif [[ "$DISTRO_LIKE" == *"rhel"* ]] || [[ "$DISTRO_LIKE" == *"fedora"* ]]; then
                DISTRO="fedora"
                install_deps
                return
            elif [[ "$DISTRO_LIKE" == *"arch"* ]]; then
                DISTRO="arch"
                install_deps
                return
            fi

            warn "Unknown distribution: $DISTRO"
            warn "Please install manually: gcc, make, pkg-config, libpq-dev, libssl-dev, postgresql"
            return 1
            ;;
    esac
}

verify_deps() {
    info "Verifying dependencies..."

    local missing=""

    if ! command -v gcc &> /dev/null; then
        missing="$missing gcc"
    fi

    if ! command -v make &> /dev/null; then
        missing="$missing make"
    fi

    if ! command -v pkg-config &> /dev/null; then
        missing="$missing pkg-config"
    fi

    if command -v pkg-config &> /dev/null; then
        if ! pkg-config --exists libpq 2>/dev/null; then
            missing="$missing libpq"
        fi

        if ! pkg-config --exists openssl 2>/dev/null; then
            missing="$missing openssl"
        fi
    fi

    if [ -n "$missing" ]; then
        error "Missing dependencies:$missing"
    fi

    info "All dependencies found"

    if command -v pkg-config &> /dev/null; then
        info "PostgreSQL: $(pkg-config --libs libpq 2>/dev/null || echo 'not found via pkg-config')"
        info "OpenSSL: $(pkg-config --libs openssl 2>/dev/null || echo 'not found via pkg-config')"
    fi
}

setup_database() {
    info "Setting up PostgreSQL database..."

    if ! command -v psql &> /dev/null; then
        warn "psql not found in PATH. Make sure PostgreSQL client is installed."
        return 1
    fi

    if command -v systemctl &> /dev/null; then
        if ! systemctl is-active --quiet postgresql 2>/dev/null; then
            warn "PostgreSQL service may not be running. Try: sudo systemctl start postgresql"
        fi
    fi

    info "To setup the database, run:"
    echo "  sudo -u postgres psql -c \"CREATE USER mmail_user WITH PASSWORD 'your_password';\""
    echo "  sudo -u postgres psql -c \"CREATE DATABASE mmail OWNER mmail_user;\""
    echo "  sudo -u postgres psql -d mmail -f docs/postgre_tables.txt"
    echo ""
    echo "Then update .env with your DB_PASSWORD"
}

build_project() {
    info "Building mmail..."
    make clean 2>/dev/null || true
    make all
    info "Build complete! Binaries in build/bin/"
}

setup_dirs() {
    info "Creating required directories..."
    mkdir -p emails logs
}

main() {
    echo "========================================"
    echo "       mmail Setup Script"
    echo "========================================"
    echo ""

    detect_distro

    case "${1:-}" in
        --deps-only)
            install_deps
            verify_deps
            ;;
        --build-only)
            verify_deps
            setup_dirs
            build_project
            ;;
        --verify)
            verify_deps
            ;;
        --db)
            setup_database
            ;;
        --help|-h)
            echo "Usage: $0 [option]"
            echo ""
            echo "Options:"
            echo "  (no option)   Full setup: install deps, verify, build"
            echo "  --deps-only   Only install system dependencies"
            echo "  --build-only  Only build (skip dependency installation)"
            echo "  --verify      Only verify dependencies are installed"
            echo "  --db          Show database setup instructions"
            echo "  --help        Show this help"
            ;;
        *)
            install_deps
            verify_deps
            setup_dirs
            build_project
            echo ""
            info "Setup complete!"
            echo ""
            setup_database
            ;;
    esac
}

main "$@"
