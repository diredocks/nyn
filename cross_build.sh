#!/bin/bash

# Exit immediately if any command fails
set -e

# Define supported architectures and their mappings
declare -A MUSL_TOOLCHAIN_MAP=(
    ["armv7"]="arm-linux-musleabihf-cross"
    ["aarch64"]="aarch64-linux-musl-cross"
    ["x86_64"]="x86_64-linux-musl-cross"
    ["i686"]="i686-linux-musl-cross"
    ["mips64"]="mips64-linux-musl-cross"
    ["riscv64"]="riscv64-linux-musl-cross"
    ["windows-amd64"]=""
)

declare -A GOARCH_MAP=(
    ["armv7"]="arm"
    ["aarch64"]="arm64"
    ["x86_64"]="amd64"
    ["i686"]="386"
    ["mips64"]="mips64"
    ["riscv64"]="riscv64"
    ["windows-amd64"]="amd64"
)

# Display supported architecture options
echo "Please choose the target architecture:"
echo -e "Architecture\tToolchain\t\t\tGo Arch"
for arch in "${!MUSL_TOOLCHAIN_MAP[@]}"; do
    toolchain=${MUSL_TOOLCHAIN_MAP[$arch]}

    if [[ -z "$toolchain" ]]; then
        toolchain="N/A"
    fi
    goarch=${GOARCH_MAP[$arch]}
    echo -e "$arch\t$toolchain\t$goarch"
done | column -t -s $'\t'  

# Prompt user for input
read -p "Enter the architecture (e.g., armv7, aarch64, windows-amd64): " ARCH

# Validate if the entered architecture is supported
if [[ ! -v MUSL_TOOLCHAIN_MAP["$ARCH"] ]]; then
    echo "Unsupported architecture: $ARCH. Supported architectures: ${!MUSL_TOOLCHAIN_MAP[@]}"
    exit 1
fi

# Set derived variables based on the selected architecture
IS_WINDOWS=false
if [[ "$ARCH" == windows* ]]; then
    IS_WINDOWS=true
fi

MUSL_TOOLCHAIN_NAME=${MUSL_TOOLCHAIN_MAP["$ARCH"]}
GOARCH=${GOARCH_MAP["$ARCH"]}
WORKSPACE_DIR=$(pwd)/cross-compile-workspace
PROJECT_DIR=$WORKSPACE_DIR/nyn
LIBPCAP_VERSION=${1:-"1.10.5"}  # Default libpcap version is 1.10.5 if not specified
NYN_REPO_URL="https://github.com/diredocks/nyn"
NYN_COMMIT=${2:-"master"}       # Default branch is master if not specified

# Create the workspace directory
mkdir -p $WORKSPACE_DIR
cd $WORKSPACE_DIR

# Step 1: Clone or update the Go project
if [ -d "$PROJECT_DIR" ]; then
    echo "Directory $PROJECT_DIR already exists. Pulling the latest changes..."
    cd $PROJECT_DIR
    git pull
    git checkout $NYN_COMMIT
else
    echo "Cloning the nyn project..."
    git clone $NYN_REPO_URL
    cd $PROJECT_DIR
    git checkout $NYN_COMMIT
fi
cd $WORKSPACE_DIR

# ========== Linux ==========
if [[ "$IS_WINDOWS" == false ]]; then
    MUSL_TOOLCHAIN_URL="https://musl.cc/${MUSL_TOOLCHAIN_NAME}.tgz"
    LIBPCAP_DIR=$WORKSPACE_DIR/libpcap-$LIBPCAP_VERSION
    MUSL_DIR=$WORKSPACE_DIR/$MUSL_TOOLCHAIN_NAME

    # Step 2: Download musl
    echo "Downloading and extracting the musl cross-compilation toolchain for $ARCH..."
    curl -LO $MUSL_TOOLCHAIN_URL
    tar -xzvf $(basename $MUSL_TOOLCHAIN_URL)

    # Step 3: Download libpcap
    echo "Downloading and extracting libpcap version $LIBPCAP_VERSION..."
    LIBPCAP_URL="https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.xz"
    curl -LO $LIBPCAP_URL
    tar -xf $(basename $LIBPCAP_URL)

    # Step 4: Build libpcap
    echo "Building libpcap version $LIBPCAP_VERSION for $ARCH..."
    cd $LIBPCAP_DIR
    TRIPLET=${MUSL_TOOLCHAIN_NAME%-cross}
    CC="$MUSL_DIR/bin/${TRIPLET}-gcc"
    ./configure --host=${TRIPLET} --with-pcap=linux --prefix="$LIBPCAP_DIR/install" CC="$CC"
    make -j$(nproc)
    make install
    cd $WORKSPACE_DIR
fi

# ========== Build ==========
echo "Building the Go project for $ARCH..."
cd $PROJECT_DIR

if [[ "$IS_WINDOWS" == true ]]; then
    # Windows 
    GOOS=windows GOARCH=$GOARCH \
        go build -ldflags "-s -w" -o "nyn-$ARCH.exe" ./cmd/nyn/
else
    # Linux 
    TRIPLET=${MUSL_TOOLCHAIN_NAME%-cross}
    CC="$MUSL_DIR/bin/${TRIPLET}-gcc"
    CGO_ENABLED=1 GOOS=linux GOARCH=$GOARCH \
        CC="$CC" \
        CGO_LDFLAGS="-L$LIBPCAP_DIR/install/lib -lpcap" \
        CGO_CFLAGS="-I$LIBPCAP_DIR/install/include" \
        go build -ldflags "-s -w" -o "nyn-$ARCH" ./cmd/nyn/
fi

echo "Build complete. Binary location:"
if [[ "$IS_WINDOWS" == true ]]; then
    echo "$PROJECT_DIR/nyn-$ARCH.exe"
else
    echo "$PROJECT_DIR/nyn-$ARCH"
fi