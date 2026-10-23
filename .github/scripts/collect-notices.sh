#!/usr/bin/env bash
set -euo pipefail
umask 022
export LC_ALL=C

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
jar=$(realpath -- "${1:?Usage: collect-notices.sh JAR MAVEN_DEPENDENCIES OUTPUT LICENSE_REPORTS}")
dependencies=$(realpath -- "${2:?Maven dependency repository layout is required}")
output=$(realpath -m -- "${3:?A new output directory is required}")
reports=$(realpath -- "${4:?Maven license reports are required}")
[[ -f "$jar" && -d "$dependencies" && ! -e "$output" &&
   -s "$reports/THIRD-PARTY-NOTICES" && -d "$reports/licenses" ]] || {
  echo 'Expected a JAR, Maven dependencies and license reports, and a new output directory.' >&2
  exit 1
}
reported_count=$(sed -n 's/^Lists of \([0-9][0-9]*\) third-party dependencies\.$/\1/p' "$reports/THIRD-PARTY-NOTICES")
[[ "$reported_count" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid Maven license report.' >&2; exit 1; }
mkdir -p -- "$(dirname -- "$output")"
work=$(mktemp -d "$(dirname -- "$output")/.notices.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/legal/dependencies" "$work/legal/boot-loader"
cp "$reports/THIRD-PARTY-NOTICES" "$work/legal/THIRD-PARTY-NOTICES"
cp -R "$reports/licenses" "$work/legal/"
printf 'jar\tsha256\tcoordinate\tmetadata\n' > "$work/legal/INVENTORY.tsv"

# Never turn an archive entry into an absolute path, traversal, or unzip pattern.
safe_entry() {
  [[ "$1" != /* && "/$1/" != */../* && "/$1/" != */./* && "$1" != *\\* &&
     "$1" != *'*'* && "$1" != *'?'* && "$1" != *'['* && "$1" != *']'* &&
     "$1" != *$'\t'* && "$1" != *$'\r'* ]]
}

extract_notices() {
  local archive=$1 destination=$2 entry basename
  unzip -Z1 "$archive" > "$work/entries.txt"
  while IFS= read -r entry; do
    [[ "$entry" != */ ]] || continue
    basename=${entry##*/}
    basename=${basename,,}
    case "$basename" in
      *.class) continue ;;
      license*|licence*|notice*|copying*|copyright*) ;;
      *) continue ;;
    esac
    # Nested libraries are processed independently below.
    [[ "$archive" != "$jar" || "$entry" != BOOT-INF/lib/* ]] || continue
    safe_entry "$entry" || { echo "Unsafe notice entry: $entry" >&2; return 1; }
    mkdir -p -- "$destination/$(dirname -- "$entry")"
    unzip -p "$archive" "$entry" > "$destination/$entry"
  done < "$work/entries.txt"
}

extract_notices "$jar" "$work/legal/boot-loader/embedded"

unzip -Z1 "$jar" > "$work/jar-entries.txt"
find "$dependencies" -type f -name '*.jar' -print > "$work/maven-jars.txt"
count=0
maven_count=0
while IFS= read -r entry; do
  [[ "$entry" == BOOT-INF/lib/*.jar ]] || continue
  safe_entry "$entry" || { echo "Unsafe library entry: $entry" >&2; exit 1; }
  name=${entry##*/}
  destination="$work/legal/dependencies/${name%.jar}"
  [[ ! -e "$destination" ]] || { echo "Duplicate library: $name" >&2; exit 1; }
  mkdir -p "$destination"
  unzip -p "$jar" "$entry" > "$work/dependency.jar"
  digest=$(sha256sum "$work/dependency.jar")
  digest=${digest%% *}
  matches=()
  while IFS= read -r candidate; do
    [[ "${candidate##*/}" != "$name" ]] || matches+=("$candidate")
  done < "$work/maven-jars.txt"
  if (( ${#matches[@]} == 1 )); then
    candidate=${matches[0]}
    cmp -s "$candidate" "$work/dependency.jar" || {
      echo "Packaged dependency differs from Maven input: $name" >&2; exit 1;
    }
    relative=${candidate#"$dependencies/"}
    version_directory=${relative%/*}
    version=${version_directory##*/}
    artifact_directory=${version_directory%/*}
    artifact=${artifact_directory##*/}
    group=${artifact_directory%/*}
    group=${group//\//.}
    coordinate="$group:$artifact:$version"
    grep -Fq "($coordinate - " "$reports/THIRD-PARTY-NOTICES" || {
      echo "Packaged dependency is missing from the Maven license report: $coordinate" >&2; exit 1;
    }
    maven_count=$((maven_count + 1))
    pom="${candidate%.jar}.pom"
    [[ -f "$pom" ]] || { echo "Missing original POM: $relative" >&2; exit 1; }
    cp -- "$pom" "$destination/upstream.pom"
    source_url="https://repo.maven.apache.org/maven2/${group//.//}/$artifact/$version/$artifact-$version-sources.jar"
    printf 'Maven repository path: %s\nOriginal artifact: https://repo.maven.apache.org/maven2/%s\nUpstream source archive: %s\n' \
      "$relative" "$relative" "$source_url" > "$destination/ORIGIN.txt"
    metadata="${relative%.jar}.pom"
  elif (( ${#matches[@]} == 0 )) && [[ "$name" == spring-boot-jarmode-tools-*.jar ]]; then
    # Boot repackage embeds this tooling library; it is not a runtime Maven dependency.
    coordinate="org.springframework.boot:spring-boot-jarmode-tools:${name#spring-boot-jarmode-tools-}"
    coordinate=${coordinate%.jar}
    group=org.springframework.boot
    artifact=spring-boot-jarmode-tools
    metadata='Spring Boot repackage tooling; embedded notices are authoritative; no runtime POM supplied'
    printf '%s\n' "$metadata" > "$destination/ORIGIN.txt"
    printf '\nAdditional Spring Boot packaging dependency:\n    (Apache License, Version 2.0) %s\n' \
      "$coordinate" >> "$work/legal/THIRD-PARTY-NOTICES"
  else
    echo "Expected exactly one matching Maven artifact: $name (${#matches[@]} found)" >&2
    exit 1
  fi
  extract_notices "$work/dependency.jar" "$destination/embedded"
  if [[ "$group" == org.springframework.session && "$version" == 4.1.1 &&
        ( "$artifact" == spring-session-core || "$artifact" == spring-session-jdbc ) ]]; then
    printf 'Upstream metadata discrepancy: the POM names Broadcom Foundation License, while this JAR embeds Apache License 2.0. Both original files are preserved here.\n' \
      >> "$destination/ORIGIN.txt"
  fi
  printf '%s\t%s\t%s\t%s\n' "$name" "$digest" "$coordinate" "$metadata" >> "$work/legal/INVENTORY.tsv"
  count=$((count + 1))
done < "$work/jar-entries.txt"
(( count > 0 )) || { echo 'No nested runtime dependencies found.' >&2; exit 1; }
(( maven_count == reported_count )) || {
  echo "Maven license report has $reported_count dependencies; the JAR contains $maven_count Maven libraries." >&2
  exit 1
}
cp "$repo/LICENSE" "$work/legal/LICENSE"
mv -- "$work/legal" "$output"
printf 'Preserved original notices and metadata for %s packaged libraries.\n' "$count"
