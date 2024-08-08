#!/bin/bash

# Exit on any error
set -e

# Define the paths relative to the current directory
SOURCE_TARBALL="inbm-0.0.0.tar.gz"
SPEC_FILE="inbm.spec"
BUILD_DIR="$HOME/rpmbuild"

# Ensure the RPM build environment is properly set up
if [ ! -d "$BUILD_DIR" ]; then
    echo "Setting up RPM build environment..."
    rpmdev-setuptree
fi

# Copy the source tarball to the SOURCES directory
echo "Copying source tarball to $BUILD_DIR/SOURCES/"
cp "$SOURCE_TARBALL" "$BUILD_DIR/SOURCES/"

# Copy the spec file to the SPECS directory
echo "Copying spec file to $BUILD_DIR/SPECS/"
cp "$SPEC_FILE" "$BUILD_DIR/SPECS/"

# Install build dependencies using dnf
echo "Installing build dependencies..."
sudo dnf builddep "$BUILD_DIR/SPECS/$SPEC_FILE"

# Build the RPM
echo "Building the RPM package..."
rpmbuild -ba "$BUILD_DIR/SPECS/$SPEC_FILE"

# Output the result
echo "Build completed successfully."
echo "Binary RPMs are located in $BUILD_DIR/RPMS/"
echo "Source RPMs are located in $BUILD_DIR/SRPMS/"
