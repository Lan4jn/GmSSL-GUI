# 现场自签名流程 "Engine request failed" 调用层故障诊断报告 (Job/RequestId: c3032cac-5146-483c-84cb-f49d478aafb5)

## 1. 故障现象与报错根因精准定位

现场用户在简单模式下点击自签名证书生成，以及访问简单首页能力目录时均报错：
```
Engine request failed (requestId: c3032cac-5146-483c-84cb-f49d478aafb5, HTTP 502)
```

### 代码抛出确切位置：
- **`platform-service/src/main/java/org/gmssl/gui/platform/Engine.java` lines 56-58**：
  ```java
  } catch (Exception e) {
    if (e instanceof InterruptedException) Thread.currentThread().interrupt();
    throw new ApiError(502, "ENGINE_UNAVAILABLE", "Engine request failed");
  }
  ```
- **重要特征**：
  - 如果 engine 服务返回了 HTTP 状态码（如 400、401、403、500 等），代码在第 51-52 行会走 `mapEngineError(res.statusCode(), data)`，抛出的 code 会被映射为 `INVALID_PARAMETERS`、`UNAUTHORIZED` 等具有具体业务语义的异常；
  - 只有当 **`http.sendAsync(...)` 底层抛出 I/O 异常（如 `HttpConnectException: Connection refused`、域名不可解析、或者连接超时 `ConnectTimeoutException`）** 时，才会被第 56 行的 `catch (Exception e)` 捕获，从而**无差别吞掉原异常栈与真实错误原因，直接包装为 502 ENGINE_UNAVAILABLE / "Engine request failed"**！
  - 此外，无论是在首页获取能力目录（`GET /capabilities` -> `engine.catalog()` -> `GET /internal/v1/catalog`），还是在证书签发首步（`CertificateWorkflowService.java:139` -> `jobs.engine.catalog()`），均需首先经由 `Engine.java` 与 engine 服务进行内部通信。一旦底层网络连接不通，直接在签发开始前、在创建实际 job 前就中断并报错。

---

## 2. 现场真实调用链与配置分析（三大优先原因）

1. **容器网络隔离或跨容器解析失败（最高概率 - 现场 JRE 镜像/Compose 运行）**：
   - 查看 `compose.jre.yaml`：
     * `engine` 服务属于网络：`networks: [backend]`，端口监听 `8081`；
     * `platform` 服务配置了：`GMSSL_ENGINE_URL: http://engine:8081`，属于网络：`networks: [frontend, backend]`。
     * 若在现场使用的是本地多进程运行模式（例如 `start-with-jre.sh` 独立启动进程，未配置 Docker network）或环境变量被错误指定为 `http://localhost:8081` / `http://engine:8081` 但宿主机无 `engine` hosts 解析，Java `HttpClient` 直连 `http://engine:8081` 立即抛出 `UnknownHostException` 或 `ConnectException`，触发第 58 行 502。
2. **engine 进程未存活或崩溃挂起（次高概率）**：
   - 现场使用的自定义 JRE 基础镜像缺少 glibc / 系统动态链接库，导致编译的 native runner 或 engine-service 进程在启动瞬间异常退出，端口 8081 处于未监听状态。
3. **安全配置与鉴权 Token 不匹配（中概率）**：
   - `compose.jre.yaml` 中 platform 和 engine 均配置了 `GMSSL_ENGINE_TOKEN`，但若 engine 返回非 JSON 或连接在建立前被 reset，同样触发此 502。

---

## 3. 现场最小只读自检与排查方案（绝无凭据/密码泄漏）

请现场运维或用户通过以下**无密钥、只读命令**排查真实底层状态：

```bash
# 1. 检查 engine 容器/进程存活状态与最近日志
docker compose -f compose.jre.yaml ps engine
docker compose -f compose.jre.yaml logs --tail 50 engine

# 2. 检查 platform 与 engine 的内部联通性（不输出任何密钥与 token）
docker compose -f compose.jre.yaml exec platform curl -s -I http://engine:8081/actuator/health
# 预期正常响应必须为 HTTP/1.1 200 OK，输出 {"status":"UP"}

# 3. 若使用非 Docker 本地进程模式运行，检查宿主机 8081 端口监听状态
curl -s -I http://127.0.0.1:8081/actuator/health
```

---

## 4. 代码层防御与可观测性改进建议

在 `Engine.java` 第 56-58 行捕获底层异常时：
- 应保留底层 `e.getClass().getSimpleName()` 与非敏感 message（如 `Connection refused` 或 `connect timed out`）记录至安全日志，与 `requestId` 关联，避免黑盒排查；
- 但对外 HTTP 响应继续保持统一安全 502，不暴露内部网络拓扑。
