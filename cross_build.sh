#!/bin/bash

# Exit immediately if any command fails
set -e

# Variables
NYN_REPO_URL="https://github.com/diredocks/nyn"
MUSL_TOOLCHAIN_BASE_URL="https://musl.cc"
LIBPCAP_VERSION=${1:-"1.10.5"}  # Default to version 1.10.5 if not specified
NYN_COMMIT=${2:-"master"}         # Default to the main branch if not specified
ARCH=${3:-"arm64"}              # Default to 'arm64' (ARM64) if not specified

# Map Go architectures to musl toolchain architecture names if needed
MUSL_ARCH=$ARCH
if [ "$ARCH" == "arm64" ]; then
    MUSL_ARCH="aarch64"
fi

WORKSPACE_DIR=$(pwd)/cross-compile-workspace
MUSL_TOOLCHAIN_URL="$MUSL_TOOLCHAIN_BASE_URL/${MUSL_ARCH}-linux-musl-cross.tgz"
MUSL_DIR=$WORKSPACE_DIR/${MUSL_ARCH}-linux-musl-cross
LIBPCAP_DIR=$WORKSPACE_DIR/libpcap-$LIBPCAP_VERSION
PROJECT_DIR=$WORKSPACE_DIR/nyn

# Create workspace directory
mkdir -p $WORKSPACE_DIR
cd $WORKSPACE_DIR

# Step 1: Clone or pull the Golang project
if [ -d "$PROJECT_DIR" ]; then
    echo "Directory $PROJECT_DIR exists. Pulling the latest changes..."
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

# Step 2: Download and extract the cross-compilation toolchain
echo "Downloading and extracting the musl cross-compilation toolchain for $ARCH..."
curl -LO $MUSL_TOOLCHAIN_URL
tar -xzvf $(basename $MUSL_TOOLCHAIN_URL)

# Step 3: Download and extract the specified version of libpcap
echo "Downloading and extracting libpcap version $LIBPCAP_VERSION..."
LIBPCAP_URL="https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.xz"
curl -LO $LIBPCAP_URL
tar -xf $(basename $LIBPCAP_URL)

# Step 4: Set up the environment for cross-compilation
echo "Setting up the cross-compilation environment for $ARCH..."
export CC="$MUSL_DIR/bin/${MUSL_ARCH}-linux-musl-gcc"
export PATH="$PATH:$MUSL_DIR/bin"

# Step 5: Build libpcap
echo "Building libpcap version $LIBPCAP_VERSION for $ARCH..."
cd $LIBPCAP_DIR
./configure --host=${MUSL_ARCH}-linux --with-pcap=linux
make -j$(nproc)
cd $WORKSPACE_DIR

# Step 6: Compile the Go project with CGO
echo "Building the Go project with CGO enabled for $ARCH..."
cd $PROJECT_DIR
CGO_ENABLED=1 GOOS=linux GOARCH=$ARCH \
    CC="$CC -I$LIBPCAP_DIR/include -L$LIBPCAP_DIR -isystem $LIBPCAP_DIR" \
    CGO_LDFLAGS="-L$LIBPCAP_DIR" \
    CGO_CFLAGS="-I$LIBPCAP_DIR/include" \
    go build -ldflags "-s -w" ./cmd/nyn/

echo "Build complete. Binary is located in the nyn directory."

