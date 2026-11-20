package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class EngineTransportTest {
  @Test
  void bodySubscriberRejectsOverflow() {
    var body = new Engine.BoundedBody(3);
    AtomicBoolean cancelled = new AtomicBoolean();
    body.onSubscribe(
        new Flow.Subscription() {
          public void request(long n) {}

          public void cancel() {
            cancelled.set(true);
          }
        });
    body.onNext(List.of(ByteBuffer.wrap(new byte[4])));
    assertTrue(cancelled.get());
    assertThrows(CompletionException.class, () -> body.getBody().toCompletableFuture().join());
  }

  @Test
  void deadlineIncludesSlowBodyAfterHeaders() throws Exception {
    var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    ExecutorService executor = Executors.newCachedThreadPool();
    server.setExecutor(executor);
    server.createContext(
        "/internal/v1/slow",
        exchange -> {
          try {
            exchange.sendResponseHeaders(200, 10);
            exchange.getResponseBody().write('{');
            exchange.getResponseBody().flush();
            Thread.sleep(3000);
            exchange.getResponseBody().write(new byte[9]);
          } catch (Exception ignored) {
          } finally {
            exchange.close();
          }
        });
    server.start();
    try {
      Engine e =
          new Engine(
              new ObjectMapper(),
              "http://127.0.0.1:" + server.getAddress().getPort(),
              "fixture-token");
      long before = System.nanoTime();
      assertThrows(ApiError.class, () -> e.request("GET", "/slow", null, 1));
      assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 2500);
    } finally {
      server.stop(0);
      executor.shutdownNow();
    }
  }

  @Test
  void transportErrorMappingSafeguards() throws Exception {
    var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    ExecutorService executor = Executors.newCachedThreadPool();
    server.setExecutor(executor);

    // 1. 400 INVALID_PARAMETERS with potential sensitive message
    server.createContext(
        "/internal/v1/err400",
        ex -> {
          byte[] b =
              "{\"code\":\"INVALID_PARAMETERS\",\"message\":\"leaked_secret_key_123456\"}".getBytes();
          ex.getResponseHeaders().set("Content-Type", "application/json");
          ex.sendResponseHeaders(400, b.length);
          ex.getResponseBody().write(b);
          ex.close();
        });

    // 2. 429 BUSY
    server.createContext(
        "/internal/v1/err429",
        ex -> {
          byte[] b = "{\"code\":\"BUSY\",\"message\":\"execution capacity reached\"}".getBytes();
          ex.getResponseHeaders().set("Content-Type", "application/json");
          ex.sendResponseHeaders(429, b.length);
          ex.getResponseBody().write(b);
          ex.close();
        });

    // 3. 401 Engine internal auth error (must map to 502, not 401)
    server.createContext(
        "/internal/v1/err401",
        ex -> {
          byte[] b = "{\"code\":\"UNAUTHORIZED\",\"message\":\"token rejected\"}".getBytes();
          ex.getResponseHeaders().set("Content-Type", "application/json");
          ex.sendResponseHeaders(401, b.length);
          ex.getResponseBody().write(b);
          ex.close();
        });

    // 4. Unknown/Malicious non-JSON message containing secrets
    server.createContext(
        "/internal/v1/errMalicious",
        ex -> {
          byte[] b = "RAW_LEAKED_PRIVATE_KEY_PLAINTEXT_SECRET_xyz789".getBytes();
          ex.getResponseHeaders().set("Content-Type", "text/plain");
          ex.sendResponseHeaders(500, b.length);
          ex.getResponseBody().write(b);
          ex.close();
        });

    server.start();
    try {
      Engine e =
          new Engine(
              new ObjectMapper(),
              "http://127.0.0.1:" + server.getAddress().getPort(),
              "test-token");

      // Verify 400: mapped to 400 INVALID_PARAMETERS, secret NOT reflected
      ApiError err400 = assertThrows(ApiError.class, () -> e.request("GET", "/err400", null, 5));
      assertEquals(400, err400.status);
      assertEquals("INVALID_PARAMETERS", err400.code);
      assertEquals("执行参数不符合工具规范", err400.getMessage());
      assertFalse(err400.getMessage().contains("123456"));
      assertFalse(err400.getMessage().contains("leaked_secret"));

      // Verify 429: mapped to 429 ENGINE_BUSY
      ApiError err429 = assertThrows(ApiError.class, () -> e.request("GET", "/err429", null, 5));
      assertEquals(429, err429.status);
      assertEquals("ENGINE_BUSY", err429.code);
      assertEquals("执行引擎繁忙，请稍后重试", err429.getMessage());

      // Verify 401: mapped to 502 ENGINE_CONFIGURATION_ERROR, NOT 401
      ApiError err401 = assertThrows(ApiError.class, () -> e.request("GET", "/err401", null, 5));
      assertEquals(502, err401.status);
      assertEquals("ENGINE_CONFIGURATION_ERROR", err401.code);
      assertEquals("执行引擎服务认证或配置异常", err401.getMessage());

      // Verify malicious/raw non-JSON: no secret reflection, mapped to 502
      ApiError errMalicious =
          assertThrows(ApiError.class, () -> e.request("GET", "/errMalicious", null, 5));
      assertEquals(502, errMalicious.status);
      assertFalse(errMalicious.getMessage().contains("RAW_LEAKED_PRIVATE_KEY"));
      assertFalse(errMalicious.getMessage().contains("xyz789"));
      assertEquals("执行引擎处理失败", errMalicious.getMessage());
    } finally {
      server.stop(0);
      executor.shutdownNow();
    }
  }
}
