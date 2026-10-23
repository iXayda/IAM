#!/usr/bin/env bash
set -euo pipefail
umask 022

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repository"

profiles=${1:?Supply the AOT profiles used for this build}
build_directory=${2:-target}
case "$profiles" in
  runtime|runtime,documentation) ;;
  *) printf 'Unsupported AOT profiles: %s\n' "$profiles" >&2; exit 1 ;;
esac

: "${JAVA_HOME:?Set JAVA_HOME to the GraalVM used for this build}"
test -x "$build_directory/iam"
test -f "$JAVA_HOME/LICENSE.txt"
test -f "$JAVA_HOME/NOTICE.txt"
test -d "$JAVA_HOME/legal"
libraries=("$build_directory"/*.so)
test -f "${libraries[0]}"

package_directory=$(mktemp -d)
trap 'rm -rf -- "$package_directory"' EXIT

cp "$build_directory/iam" "${libraries[@]}" LICENSE "$package_directory/"
chmod 0755 "$package_directory/iam"
chmod 0644 "$package_directory/"*.so "$package_directory/LICENSE"

oracle_notices="$package_directory/legal/oracle-graalvm"
mkdir -p "$oracle_notices"
cp "$JAVA_HOME/LICENSE.txt" "$JAVA_HOME/NOTICE.txt" "$oracle_notices/"
# GraalVM's legal tree uses links between modules; preserve their actual text.
cp -RL "$JAVA_HOME/legal" "$oracle_notices/"
chmod 0755 "$package_directory"

{
  printf 'Source commit: %s\n' "${GITHUB_SHA:-$(git rev-parse HEAD)}"
  printf 'AOT profiles: %s\n' "$profiles"
  printf 'Build platform: %s\n' "$(uname -srm)"
  "$JAVA_HOME/bin/java" -version 2>&1
  getconf GNU_LIBC_VERSION
  printf '\nELF platform and CPU requirements:\n'
  file "$build_directory/iam"
  readelf --notes "$build_directory/iam"
  printf '\nRequired glibc symbol versions (executable and bundled libraries):\n'
  readelf --version-info "$build_directory/iam" "${libraries[@]}" \
    | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)*' | sort -Vu
  printf '\nDynamic dependencies of the Web executable:\n'
  ldd "$build_directory/iam"
} > "$package_directory/BUILD-INFO.txt"

tar --create --gzip --file "$build_directory/iam-native.tar.gz.partial" \
  --directory "$package_directory" .
mv "$build_directory/iam-native.tar.gz.partial" "$build_directory/iam-native.tar.gz"
