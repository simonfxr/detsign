#!/usr/bin/env bash

: "${VSBUILDTOOLS:=$HOME/opt/vs-build-tools}"

D="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
build_type="${1:-debug}"
host_arch="${2:-$(uname -m)}"
build_config="${build_type}-clangcl-make-${host_arch}-xwin10"
build_dir="${D}/build/${build_config}"

capitalize() {
    local first="${1:0:1}" rest="${1:1}"
    echo "${first^^}${rest,,}"
}

set -e

WINSDK_BASE="${VSBUILDTOOLS}/winsdk_base_10"
WINSDK_VER="$(
  cd "${WINSDK_BASE}/Lib" || exit 1;
  command ls -1 | sort -r | head -1)"

mkdir -p "$build_dir"
cd "$build_dir"
exec cmake \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=True \
    -DCMAKE_BUILD_TYPE="$(capitalize "$build_type")" \
    -DCMAKE_TOOLCHAIN_FILE="${D}/cmake-toolchains/win-msvc/WinMsvc.cmake" \
    -DHOST_ARCH="$host_arch" \
    -DLLVM_NATIVE_TOOLCHAIN="/usr" \
    -DMSVC_BASE="${VSBUILDTOOLS}/msvc_base" \
    -DWINSDK_BASE="$WINSDK_BASE" \
    -DWINSDK_VER="$WINSDK_VER" \
    ../..
