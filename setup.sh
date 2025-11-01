#!/bin/bash
# Advanced Network Packet Analyzer - Automated Setup Script
# This script sets up the complete environment for the packet analyzer

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║   Advanced Network Packet Analyzer - Setup Script       ║"
    echo "║                    Version 2.0.0                         ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is OK for system dependencies."
        print_warning "Python packages will be installed for current user."
        return 0
    else
        return 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VER=$(lsb_release -sr)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    print_info "Detected OS: $OS $VER"
}

install_system_deps() {
    print_info "Installing system dependencies..."
    
    case "$OS" in
        ubuntu|debian)
            print_step "Installing packages for Ubuntu/Debian..."
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip python3-venv tcpdump libpcap-dev git
            ;;
        fedora)
            print_step "Installing packages for Fedora..."
            sudo dnf install -y python3 python3-pip tcpdump libpcap-devel git
            ;;
        centos|rhel)
            print_step "Installing packages for CentOS/RHEL..."
            sudo yum install -y python3 python3-pip tcpdump libpcap-devel git
            ;;
        arch|manjaro)
            print_step "Installing packages for Arch Linux..."
            sudo pacman -S --noconfirm python python-pip tcpdump libpcap git
            ;;
        *)
            print_error "Unsupported OS: $OS"
            print_info "Please install manually: python3, pip, tcpdump, libpcap-dev"
            exit 1
            ;;
    esac
    
    print_step "System dependencies installed successfully"
}

check_python() {
    print_info "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | awk '{print $2}')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
            print_step "Python $PYTHON_VERSION detected (OK)"
            return 0
        else
            print_error "Python 3.8+ required, found $PYTHON_VERSION"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

setup_venv() {
    print_info "Setting up Python virtual environment..."
    
    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists"
        read -p "Recreate? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf venv
        else
            print_info "Using existing virtual environment"
            return 0
        fi
    fi
    
    python3 -m venv venv
    source venv/bin/activate
    
    print_step "Virtual environment created"
}

install_python_deps() {
    print_info "Installing Python dependencies..."
    
    # Activate virtual environment if it exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    # Upgrade pip
    python3 -m pip install --upgrade pip -q
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        python3 -m pip install -r requirements.txt -q
        print_step "Python dependencies installed from requirements.txt"
    else
        print_warning "requirements.txt not found, installing core dependencies..."
        python3 -m pip install scapy rich -q
        print_step "Core dependencies installed"
    fi
    
    # Verify installation
    python3 -c "import scapy; import rich" 2>/dev/null
    if [ $? -eq 0 ]; then
        print_step "Dependencies verified successfully"
    else
        print_error "Dependency verification failed"
        return 1
    fi
}

create_directories() {
    print_info "Creating project directories..."
    
    mkdir -p captures
    mkdir -p docs/images
    mkdir -p examples
    mkdir -p tests
    
    # Create .gitkeep for empty directories
    touch captures/.gitkeep
    touch docs/images/.gitkeep
    
    print_step "Directories created"
}

set_permissions() {
    print_info "Setting file permissions..."
    
    # Make main script executable
    if [ -f "packet_analyzer.py" ]; then
        chmod +x packet_analyzer.py
        print_step "packet_analyzer.py is executable"
    fi
    
    # Make example scripts executable
    if [ -d "examples" ]; then
        chmod +x examples/*.sh 2>/dev/null || true
        print_step "Example scripts are executable"
    fi
}

test_installation() {
    print_info "Testing installation..."
    
    # Activate venv if exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    # Test 1: Check version
    if python3 packet_analyzer.py --version 2>&1 | grep -q "2.0.0"; then
        print_step "Version check passed"
    else
        print_error "Version check failed"
        return 1
    fi
    
    # Test 2: List interfaces (requires root)
    if check_root || sudo -n true 2>/dev/null; then
        if sudo python3 packet_analyzer.py --list-interfaces &>/dev/null; then
            print_step "Interface listing passed"
        else
            print_warning "Interface listing requires root privileges"
        fi
    else
        print_warning "Skipping interface test (requires sudo)"
    fi
    
    print_step "Installation tests passed"
}

create_quick_start_script() {
    print_info "Creating quick start script..."
    
    cat > run.sh << 'EOF'
#!/bin/bash
# Quick start script for Advanced Network Packet Analyzer

# Activate virtual environment if exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges for packet capture."
    echo "Running with sudo..."
    sudo -E env "PATH=$PATH" python3 packet_analyzer.py "$@"
else
    python3 packet_analyzer.py "$@"
fi
EOF
    
    chmod +x run.sh
    print_step "Created run.sh quick start script"
}

print_usage_info() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Installation Complete!                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Quick Start:${NC}"
    echo "  1. Activate virtual environment:"
    echo "     source venv/bin/activate"
    echo ""
    echo "  2. Run basic capture:"
    echo "     sudo python3 packet_analyzer.py"
    echo ""
    echo "  3. Or use quick start script:"
    echo "     ./run.sh"
    echo ""
    echo -e "${BLUE}Common Commands:${NC}"
    echo "  # Capture with IDS"
    echo "  sudo python3 packet_analyzer.py --ids --alerts"
    echo ""
    echo "  # Monitor HTTP traffic"
    echo "  sudo python3 packet_analyzer.py -f 'tcp port 80 or tcp port 443'"
    echo ""
    echo "  # Capture to files"
    echo "  sudo python3 packet_analyzer.py -c 100 --pcap --csv --json"
    echo ""
    echo -e "${BLUE}Example Scripts:${NC}"
    echo "  ./examples/basic_capture.sh"
    echo "  ./examples/security_scan.sh"
    echo "  ./examples/http_monitor.sh"
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo "  README.md           - Main documentation"
    echo "  TESTING.md          - Testing guide"
    echo "  CONTRIBUTING.md     - Contribution guidelines"
    echo ""
    echo -e "${YELLOW}⚠️  Remember:${NC}"
    echo "  - Only use on networks you own or have authorization"
    echo "  - Run with sudo for packet capture"
    echo "  - Check firewall settings if no packets captured"
    echo ""
    echo -e "${GREEN}Happy packet analyzing! 🔍${NC}"
    echo ""
}

cleanup_on_error() {
    print_error "Setup failed. Cleaning up..."
    # Could add cleanup steps here
    exit 1
}

# Main installation flow
main() {
    trap cleanup_on_error ERR
    
    print_header
    
    echo "This script will:"
    echo "  1. Detect your operating system"
    echo "  2. Install system dependencies"
    echo "  3. Set up Python virtual environment"
    echo "  4. Install Python packages"
    echo "  5. Create project directories"
    echo "  6. Test the installation"
    echo ""
    
    read -p "Continue with installation? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled"
        exit 0
    fi
    
    echo ""
    
    # Installation steps
    detect_os
    echo ""
    
    install_system_deps
    echo ""
    
    check_python || exit 1
    echo ""
    
    setup_venv
    echo ""
    
    install_python_deps || exit 1
    echo ""
    
    create_directories
    echo ""
    
    set_permissions
    echo ""
    
    create_quick_start_script
    echo ""
    
    test_installation
    echo ""
    
    print_usage_info
}

# Run main function
main "$@"