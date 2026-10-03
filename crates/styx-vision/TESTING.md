# styx-vision 测试说明

- 测试完成：是（2026-10-04）
- 测试日期：2026-10-04
- 测试内容：单元覆盖 styx-http（URL 解析）与 styx-vision（PNG/BMP/JPEG 解码、inflate、事实提取、标签归组、Composer 后端合并）；集成覆盖 JPEG 与 libjpeg 逐像素比对、畸形图片字节鲁棒性；注入测试覆盖 URL 协议/端口守卫、伪造巨尺寸/截断/负尺寸图片字节不 panic 安全降级；钩子测试覆盖 Composer 可插拔后端链——注册顺序即触发顺序、一个后端报错不中断兄弟后端。
- 运行命令：`cargo test -p styx-http` / `cargo test -p styx-vision`（`--features http` 开远程后端解析）
- 测试框架：Rust #[cfg(test)]
- 模型：豆包（Doubao）生成

这是一个 cargo workspace，两个 crate：

| crate | 作用 | 测试位置 |
|---|---|---|
| `crates/styx-http` | 极简同步 HTTP 客户端 | `src/url.rs` 等内 `#[cfg(test)]`（无根 package，无独立 tests/） |
| `crates/styx-vision` | 零依赖 PNG/BMP/JPEG 解码 + 事实提取 + 可插拔后端 | 单元在 `src/*.rs`；集成在 `tests/` |

## 测试放在哪里

- 单元：各 `src/*.rs` 的 `#[cfg(test)]`（解码、inflate、JPEG、事实、归组、URL 解析、后端合并）。
- 集成：`crates/styx-vision/tests/`
  - `jpeg_reference.rs` — 与 libjpeg 逐像素比对（既有，3）。
  - `live_sidecar.rs` — 需要真 sidecar，`#[ignore]`（既有）。
  - **`robustness.rs` — 解码器注入/鲁棒性（本次新增，4）**。

## 怎么运行

```powershell
# 全量（本地路径，零网络依赖）
cargo test < NUL

# 两个 crate 分别
cargo test -p styx-http        # URL 解析
cargo test -p styx-vision      # 解码 + 事实 + 后端 + robustness

# 打开远程后端的解析逻辑
cargo test --features http

# 需要真 sidecar 的整链
cargo test --features http --test live_sidecar -- --ignored --nocapture
```

## 预期结果（本地基线）

| target | 结果 |
|---|---|
| `styx-http` 单元 | 22 passed, 0 failed |
| `styx-vision` 单元 | 75 passed, 0 failed |
| `tests/jpeg_reference` | 3 passed |
| `tests/robustness`（新增） | 4 passed |
| `live_sidecar` | 0 run（1 个 `#[ignore]`） |

### 本次补强新增

**注入测试 +7**：
- `styx-http/src/url.rs` 单元 +3：
  - `rejects_non_http_schemes_that_become_file_or_script` — `file://`、`javascript:`、`data:`、`gopher:`、`ftp:`、`ws:` 一律拒（SSRF/协议注入守卫）。
  - `rejects_garbage_ports` — 端口越界（99999）、非数字、空端口当场报错。
  - `userinfo_is_stripped_and_host_is_literal` — `user:pw@host` 里的 userinfo 不得泄漏进 Host。
- `crates/styx-vision/tests/robustness.rs` 集成 +4：
  - `malformed_bytes_never_panic_and_safely_degrade` — 空/全 0/全 1/截断 PNG·JPEG·BMP/XSS 文本/SQL 文本，喂给 `analyze/decode/dimensions/sniff` 不 panic、`decoded=false`。
  - `png_claiming_huge_dimensions_is_rejected_not_ooms` — 伪造 0x7fff_ffff 宽高的 PNG 不 OOM、不溢出、被拒。
  - `negative_or_zero_dimensions_in_bmp_header_are_safe` — BMP 头负宽/负高不越界。
  - `path_traversal_or_shell_metachars_in_bytes_are_treated_as_opaque_data` — `../../etc/passwd`、`; rm -rf` 仅作像素数据，不泄漏进描述。

**钩子/后端链测试 +1**：
- `styx-vision/src/backend.rs` `a_failing_backend_does_not_stop_siblings_in_registration_order` —
  先注册的后端 detect 报错，紧随其后的兄弟后端仍被调用、结果仍合并；失败只记一条 note，
  注册顺序即触发顺序，失败后端不中断整条链（`Composer` 的可插拔后端 = 钩子机制）。
