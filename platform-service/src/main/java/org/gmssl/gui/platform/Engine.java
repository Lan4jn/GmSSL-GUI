package org.gmssl.gui.platform;

import com.fasterxml.jackson.databind.*;
import java.io.ByteArrayOutputStream;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
class Engine {
  final HttpClient http =
      HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(5))
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();
  final String base, token;
  final ObjectMapper json;

  Engine(
      ObjectMapper j,
      @Value("${GMSSL_ENGINE_URL:http://127.0.0.1:8081}") String b,
      @Value("${GMSSL_ENGINE_TOKEN:}") String t) {
    json = j;
    base = b.replaceAll("/$", "");
    token = t;
    if (t.isBlank()) throw new IllegalStateException("Engine token required");
    URI uri = URI.create(base);
    if (!Set.of("http", "https").contains(uri.getScheme()) || uri.getUserInfo() != null)
      throw new IllegalStateException("Invalid configured engine URL");
  }

  JsonNode request(String method, String path, Object body, int timeout) {
    CompletableFuture<HttpResponse<byte[]>> response = null;
    try {
      var rb =
          HttpRequest.newBuilder(URI.create(base + "/internal/v1" + path))
              .timeout(Duration.ofSeconds(timeout))
              .header("X-Engine-Token", token);
      if (body == null) rb.method(method, HttpRequest.BodyPublishers.noBody());
      else
        rb.header("Content-Type", "application/json")
            .method(method, HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(body)));
      response = http.sendAsync(rb.build(), info -> new BoundedBody(48 * 1024 * 1024));
      var res = response.get(timeout, TimeUnit.SECONDS);
      byte[] data = res.body();
      if (res.statusCode() < 200 || res.statusCode() >= 300)
        throw mapEngineError(res.statusCode(), data);
      return data.length == 0 ? json.createObjectNode() : json.readTree(data);
    } catch (ApiError e) {
      throw e;
    } catch (Exception e) {
      if (e instanceof InterruptedException) Thread.currentThread().interrupt();
      throw new ApiError(502, "ENGINE_UNAVAILABLE", "Engine request failed");
    } finally {
      if (response != null && !response.isDone()) response.cancel(true);
    }
  }

  private ApiError mapEngineError(int statusCode, byte[] data) {
    String engineCode = null;
    if (data != null && data.length > 0) {
      try {
        JsonNode tree = json.readTree(data);
        if (tree.has("code") && tree.get("code").isTextual()) {
          engineCode = tree.get("code").asText();
        }
      } catch (Exception ignored) {
        // Non-JSON or malformed payload, drop to prevent raw message reflection
      }
    }
    return mapEngineCode(statusCode, engineCode);
  }

  static ApiError mapEngineCode(int statusCode, String engineCode) {
    // 1. Internal engine configuration/auth errors (401/403)
    // Must remain 502 with fixed safe message to avoid masquerading as user session expiry.
    if (statusCode == 401 || statusCode == 403) {
      return new ApiError(502, "ENGINE_CONFIGURATION_ERROR", "执行引擎服务认证或配置异常");
    }

    // 2. Client/Parameter errors (400)
    if (statusCode == 400) {
      if ("INVALID_PARAMETERS".equals(engineCode)) {
        return new ApiError(400, "INVALID_PARAMETERS", "执行参数不符合工具规范");
      }
      if ("INVALID_REQUEST".equals(engineCode)) {
        return new ApiError(400, "INVALID_REQUEST", "执行请求格式非法");
      }
      if ("TOOL_UNAVAILABLE".equals(engineCode) || "UNAVAILABLE".equals(engineCode)) {
        return new ApiError(400, "TOOL_UNAVAILABLE", "工具在当前环境中不可用");
      }
      if ("UNKNOWN_TOOL".equals(engineCode)) {
        return new ApiError(400, "UNKNOWN_TOOL", "未知或不支持的工具");
      }
      if ("NETWORK_POLICY".equals(engineCode)) {
        return new ApiError(400, "NETWORK_POLICY_VIOLATION", "网络策略禁止该目标访问");
      }
      if ("SECRET_DIAGNOSTICS".equals(engineCode)) {
        return new ApiError(400, "SECRET_DIAGNOSTICS_FORBIDDEN", "协议密钥诊断已被系统禁用");
      }
      if ("INVALID_CERTIFICATE".equals(engineCode)) {
        return new ApiError(400, "INVALID_CERTIFICATE", "证书数据非法或无法解析");
      }
      if ("INVALID_CRL".equals(engineCode)) {
        return new ApiError(400, "INVALID_CRL", "CRL 格式或签名校验失败");
      }
      return new ApiError(400, "INVALID_PARAMETERS", "执行参数不符合工具规范");
    }

    // 3. Conflict / Duplicate execution (409)
    if (statusCode == 409) {
      return new ApiError(409, "DUPLICATE_EXECUTION", "执行标识已被占用");
    }

    // 4. Payload/Input/Output limits (413)
    if (statusCode == 413) {
      return new ApiError(413, "PAYLOAD_TOO_LARGE", "输入或输出数据超过大小限制");
    }

    // 5. Engine busy / Rate limit (429)
    if (statusCode == 429) {
      return new ApiError(429, "ENGINE_BUSY", "执行引擎繁忙，请稍后重试");
    }

    // 6. Service unavailable / Quarantine (503)
    if (statusCode == 503) {
      return new ApiError(503, "ENGINE_UNAVAILABLE", "执行引擎服务暂时不可用");
    }

    // 7. Timeout (504)
    if (statusCode == 504) {
      return new ApiError(504, "ENGINE_TIMEOUT", "执行引擎处理超时");
    }

    // Default for any other non-2xx
    return new ApiError(502, "ENGINE_ERROR", "执行引擎处理失败");
  }

  static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
    final int limit;
    final CompletableFuture<byte[]> result = new CompletableFuture<>();
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    Flow.Subscription subscription;

    BoundedBody(int limit) {
      this.limit = limit;
    }

    public CompletionStage<byte[]> getBody() {
      return result;
    }

    public void onSubscribe(Flow.Subscription s) {
      subscription = s;
      s.request(1);
    }

    public void onNext(List<ByteBuffer> buffers) {
      try {
        for (ByteBuffer b : buffers) {
          if (b.remaining() > limit - out.size())
            throw new IllegalStateException("Engine response exceeds limit");
          byte[] bytes = new byte[b.remaining()];
          b.get(bytes);
          out.writeBytes(bytes);
        }
        subscription.request(1);
      } catch (Exception e) {
        subscription.cancel();
        result.completeExceptionally(e);
      }
    }

    public void onError(Throwable e) {
      result.completeExceptionally(e);
    }

    public void onComplete() {
      result.complete(out.toByteArray());
    }
  }

  JsonNode catalog() {
    return request("GET", "/capabilities", null, 10);
  }

  JsonNode keyGenerationCapabilities() {
    return request("GET", "/key-generation-capabilities", null, 10);
  }

  JsonNode keyGeneration(Map<String, Object> body, int timeoutSeconds) {
    return request("POST", "/key-generations", body, timeoutSeconds);
  }

  JsonNode tool(String id) {
    for (JsonNode t : catalog().path("tools"))
      if (t.path("id").asText().equals(id)) {
        if (t.path("verification").path("status").asText().equals("unavailable"))
          throw ApiError.bad("Tool unavailable");
        return t;
      }
    throw ApiError.bad("Unknown tool");
  }
}
