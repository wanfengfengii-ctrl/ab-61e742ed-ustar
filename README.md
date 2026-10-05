# TAR Bundle Attestation Service

隔离环境用的 TAR 配置包校验与摘要服务（Python 标准库，零运行时依赖）。

## 接口

### `POST /api/bundles/attest`

- `Content-Type: application/x-tar`，必须带 `Content-Length`，未压缩 USTAR，
  请求体 ≤ 8 MiB（拒绝 `Content-Encoding` 与 chunked 请求）。
- 包内要求：
  - 1–100 个普通文件（typeflag 仅 `0`/`\0`），文件内容合计 ≤ 6 MiB；
  - 路径为 UTF-8 NFC 相对路径，仅以 `/` 分段；禁止空段、`.`/`..` 段、
    反斜杠、控制字符、绝对路径与重复项（含 prefix/name 拆分等价重复）；
  - 仅接受标准 USTAR 头（`ustar\0` + `00`）、校验和正确、规范八进制字段、
    完整数据块、零填充和恰好两个零结束块；其后只允许零字节记录填充。
- 成功响应（路径按 UTF-8 字节序）：

  ```json
  {
    "files": [{"path": "a.txt", "size": 5, "sha256": "<hex>" }],
    "bundleSha256": "<hex>"
  }
  ```

  `bundleSha256 = SHA256( concat( be32(pathlen) || pathbytes || be64(size) || sha256(content) ) )`。
- 任何越界/非 USTAR/链接/截断/尾部非零/歧义路径均拒绝，响应形如
  `{"error": {"category": "bad_checksum", "message": "entry 2: ..."}}`，
  绝不返回部分清单。错误类别包括：`bad_checksum`、`non_ustar`、
  `unsupported_type`、`invalid_header`、`invalid_path`、`duplicate_path`、
  `truncated`、`invalid_padding`、`invalid_terminator`、`trailing_data`、
  `empty_archive`、`too_many_files`、`content_too_large`、`bundle_too_large`、
  `unsupported_media_type`、`compressed_or_encoded` 等。

### `GET /health`

返回 `200 {"status":"ok"}`。

## 运行

```bash
# 宿主机端口可配置（默认 8080）
BUNDLE_HOST_PORT=18080 docker compose up --build web

# 一次性验收：单元测试 + 构建编译检查 + 冒烟（有效包 / 坏校验和 / 路径冲突）
docker compose build web verify
docker compose run --rm verify   # 退出码 0 表示全部通过
```

非容器方式：

```bash
BUNDLE_PORT=8080 python -m app.server
python scripts/verify.py         # 自动启动本地服务并跑全部检查
python -m unittest discover -s tests
```

## 布局

- `app/tarparser.py` — 手写严格 USTAR 解析与摘要；
- `app/server.py` — HTTP 服务；
- `tests/` — 解析器、HTTP、标准库互操作测试；
- `scripts/verify.py` — Compose `verify` 一次性服务入口；
- `Dockerfile` / `compose.yaml`。
