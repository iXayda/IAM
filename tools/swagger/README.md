# OpenAPI 独立预览

读取已导出的 OpenAPI 规范，在本地校验并通过只读 Swagger UI 预览。规范的导出入口见 [IAM 接口文档](../../README.md#接口文档工具)。

需要可用的 Docker Compose。以下命令在仓库根目录执行，将 `OPENAPI_DIR` 设置为规范目录的绝对路径，`OPENAPI_FILE` 设置为目录内的文件路径，支持 YAML 和 JSON：

```bash
export OPENAPI_DIR=/absolute/path/to/openapi
export OPENAPI_FILE=openapi.yaml
docker compose -f tools/swagger/compose.yaml run --rm validate
docker compose -f tools/swagger/compose.yaml up -d ui
```

打开 <http://127.0.0.1:8081> 查看文档。预览启动前会校验规范；通过 `SWAGGER_PORT` 调整本地端口。规范及相对引用文件应位于 `OPENAPI_DIR` 目录树内，该目录以只读方式挂载。校验在本地容器中执行，页面关闭在线校验和接口调用。

停止并移除预览容器：

```bash
docker compose -f tools/swagger/compose.yaml down
```
