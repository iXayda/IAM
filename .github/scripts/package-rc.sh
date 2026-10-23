#!/usr/bin/env bash
set -euo pipefail
umask 022

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repository"

version=${1:?Supply the RC version from pom.xml}
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.(0|[1-9][0-9]*)$ ]]; then
  printf 'Expected an x.y.z-rc.N version\n' >&2
  exit 1
fi

: "${GITHUB_SERVER_URL:?Supply the source server URL}"
: "${GITHUB_REPOSITORY:?Supply the source repository}"
source_commit=${GITHUB_SHA:?Supply the workflow source commit}
test "$source_commit" = "$(git rev-parse HEAD)"
git diff --quiet "$source_commit" -- .
test ! -e target/rc

inputs=target/rc-inputs
jar="$inputs/jar/iam.jar"
native="$inputs/native/iam-native.tar.gz"
test -f "$jar"
test -f "$native"
test -d target/rc-dependencies

jar_version=$(unzip -p "$jar" META-INF/MANIFEST.MF | tr -d '\r' | sed -n 's/^Implementation-Version: //p')
test "$jar_version" = "$version"

staging=$(mktemp -d target/rc-staging.XXXXXX)
trap 'rm -rf -- "$staging"' EXIT
mkdir "$staging/output" "$staging/native"
output="$staging/output"
prefix="iam-$version"

cp "$jar" "$output/$prefix.jar"
git archive --format=tar.gz --prefix="$prefix/" "$source_commit" \
  > "$output/$prefix-source.tar.gz"

tar --extract --gzip --file "$native" --directory "$staging/native" \
  --no-same-owner --no-same-permissions
test -x "$staging/native/iam"
test -d "$staging/native/legal/oracle-graalvm"
grep -Fx "Source commit: $source_commit" "$staging/native/BUILD-INFO.txt"
grep -Fx 'AOT profiles: runtime' "$staging/native/BUILD-INFO.txt"

bash .github/scripts/collect-notices.sh "$jar" target/rc-dependencies "$staging/legal" target/third-party
cp -R "$staging/legal/." "$staging/native/legal/"
cp -R "$staging/native/legal/oracle-graalvm" "$staging/legal/"
chmod 0755 "$staging/native"

tar --create --gzip --file "$output/$prefix-native-linux-amd64.tar.gz" \
  --directory "$staging/native" .
tar --create --gzip --file "$output/$prefix-licenses.tar.gz" \
  --directory "$staging" legal

for runtime in jvm native; do
  image_archive="$prefix-image-$runtime-linux-amd64.tar.gz"
  archive="$inputs/$runtime-image/$image_archive"
  test -f "$archive"
  gzip --test "$archive"
  cp "$archive" "$output/$image_archive"
done

cp "$staging/native/BUILD-INFO.txt" "$output/NATIVE-BUILD-INFO.txt"
{
  printf 'Version: %s\nSource commit: %s\n' "$version" "$source_commit"
  printf 'Source: %s/%s/tree/%s\n' "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$source_commit"
  if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
    printf 'Workflow: %s/%s/actions/runs/%s\n' \
      "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID"
  fi
} > "$output/SOURCE.txt"

cat > "$output/RELEASE-NOTES.md" <<EOF
# IAM $version

这是供验证的候选版本。源码、安装说明及数据库授权脚本见源码包；使用前执行 \`sha256sum --check SHA256SUMS\`。

## 运行要求

| 运行方式 | 环境要求 |
| --- | --- |
| JAR | Oracle JDK 21 |
| 原生程序 | Linux amd64、glibc 和 zlib 运行库；保留程序同目录的共享库。具体 CPU、glibc 和动态库要求见 \`NATIVE-BUILD-INFO.txt\` |
| JVM / Native 容器 | 支持 Linux amd64 容器的 Docker，Java 或原生运行依赖已包含在镜像中；使用仓库 Compose 配置时还需 Docker Compose 2.20.2+ |

运行 Web 服务需已完成安装和初始化的 PostgreSQL 18 及持久保护密钥。IAM 可直接提供 HTTPS，也可由受信代理终止 TLS 后通过受保护内网 HTTP 回源；对外 issuer 必须使用 HTTPS。数据库权限、身份前端和环境变量配置见源码包 README。

原生程序仅运行 Web 服务，无需安装 GraalVM 或编译工具链；数据库迁移、密钥和管理员初始化等维护操作使用同版本 JAR。

## 发行文件

- JVM 和 Native 镜像通过 \`docker load\` 导入，镜像名为 \`iam:$version-jvm\` 和 \`iam:$version-native\`。
- 该工作流完成 Java、应用示例、浏览器及原生验证，并检查镜像构建、归档和加载；部署环境仍须验收证书、密钥、数据库权限及实际运行。
- 项目及依赖许可见 \`$prefix-licenses.tar.gz\`；原生包也包含相应声明，镜像内的应用声明位于 \`/apps/iam/legal\`。

源码提交：$source_commit。来源及工作流入口见 \`SOURCE.txt\`。
EOF

(
  cd "$output"
  sha256sum -- * > SHA256SUMS
  sha256sum --check SHA256SUMS
)
mv -T "$output" target/rc
