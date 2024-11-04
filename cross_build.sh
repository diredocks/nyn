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
)

declare -A GOARCH_MAP=(
    ["armv7"]="arm"
    ["aarch64"]="arm64"
    ["x86_64"]="amd64"
    ["i686"]="386"
    ["mips64"]="mips64"
    ["riscv64"]="riscv64"
)

# Display supported architecture options
echo "Please choose the target architecture:"
echo -e "Architecture\tToolchain\t\t\tGo Arch"
for arch in "${!MUSL_TOOLCHAIN_MAP[@]}"; do
    toolchain=${MUSL_TOOLCHAIN_MAP[$arch]}
    goarch=${GOARCH_MAP[$arch]}
    echo -e "$arch\t\t$toolchain\t\t$goarch"
done | column -t

# Prompt user for input
read -p "Enter the architecture (e.g., armv7, aarch64, x86_64, i686, mips64, riscv64): " ARCH

# Validate if the entered architecture is supported
if [[ ! -v MUSL_TOOLCHAIN_MAP["$ARCH"] ]]; then
    echo "Unsupported architecture: $ARCH. Supported architectures: ${!MUSL_TOOLCHAIN_MAP[@]}"
    exit 1
fi

# Set derived variables based on the selected architecture
MUSL_TOOLCHAIN_NAME=${MUSL_TOOLCHAIN_MAP["$ARCH"]}
GOARCH=${GOARCH_MAP["$ARCH"]}
MUSL_TOOLCHAIN_URL="https://musl.cc/${MUSL_TOOLCHAIN_NAME}.tgz"

WORKSPACE_DIR=$(pwd)/cross-compile-workspace
MUSL_DIR=$WORKSPACE_DIR/$MUSL_TOOLCHAIN_NAME
LIBPCAP_VERSION=${1:-"1.10.5"}  # Default libpcap version is 1.10.5 if not specified
LIBPCAP_DIR=$WORKSPACE_DIR/libpcap-$LIBPCAP_VERSION
NYN_REPO_URL="https://github.com/diredocks/nyn"
NYN_COMMIT=${2:-"master"}       # Default branch is master if not specified
PROJECT_DIR=$WORKSPACE_DIR/nyn

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

# Step 2: Download and extract the musl cross-compilation toolchain
echo "Downloading and extracting the musl cross-compilation toolchain for $ARCH..."
curl -LO $MUSL_TOOLCHAIN_URL
tar -xzvf $(basename $MUSL_TOOLCHAIN_URL)

# Step 3: Download and extract the specified version of libpcap
echo "Downloading and extracting libpcap version $LIBPCAP_VERSION..."
LIBPCAP_URL="https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.xz"
curl -LO $LIBPCAP_URL
tar -xf $(basename $LIBPCAP_URL)

# Step 4: Set up the cross-compilation environment
echo "Setting up the cross-compilation environment for $ARCH..."
TRIPLET=${MUSL_TOOLCHAIN_NAME%-cross}
export CC="$MUSL_DIR/bin/${TRIPLET}-gcc"
export PATH="$PATH:$MUSL_DIR/bin"

# Step 5: Build libpcap
echo "Building libpcap version $LIBPCAP_VERSION for $ARCH..."
cd $LIBPCAP_DIR
./configure --host=${TRIPLET} --with-pcap=linux
make -j$(nproc)
cd $WORKSPACE_DIR

# Step 6: Compile the Go project with CGO enabled
echo "Building the Go project with CGO enabled for $ARCH..."
cd $PROJECT_DIR
CGO_ENABLED=1 GOOS=linux GOARCH=$GOARCH \
    CC="$CC -I$LIBPCAP_DIR/include -L$LIBPCAP_DIR -isystem $LIBPCAP_DIR" \
    CGO_LDFLAGS="-L$LIBPCAP_DIR" \
    CGO_CFLAGS="-I$LIBPCAP_DIR/include" \
    go build -ldflags "-s -w" ./cmd/nyn/

echo "Build complete. The binary is located in the nyn directory."