package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.Test;

class KeyGenerationBudgetTest {
  @Test
  void internalBudgetBoundsEngineAndTransportWithoutPublicOverride() {
    Engine engine = mock(Engine.class);
    KeyGenerationService service = new KeyGenerationService(
        engine, mock(Materials.class), mock(CredentialService.class), mock(Store.class));
    ApiError stop = new ApiError(502, "ENGINE_UNAVAILABLE", "fixture stop");
    when(engine.keyGeneration(anyMap(), anyInt())).thenThrow(stop);
    assertSame(stop, assertThrows(ApiError.class, () -> service.generateWithTimeout(
        "project", "user", Map.of("algorithm", "SM2", "timeoutSeconds", 300), 1)));
    verify(engine).keyGeneration(argThat(body -> Integer.valueOf(1).equals(body.get("timeoutSeconds"))), eq(1));
    clearInvocations(engine);
    assertThrows(ApiError.class, () -> service.generateWithTimeout("project", "user", Map.of("algorithm", "SM2"), 0));
    verifyNoInteractions(engine);
    assertSame(stop, assertThrows(ApiError.class, () -> service.generate(
        "project", "user", Map.of("algorithm", "SM2", "timeoutSeconds", 300))));
    verify(engine).keyGeneration(argThat(body -> Integer.valueOf(30).equals(body.get("timeoutSeconds"))), eq(30));
  }

  @Test
  void generationRejectsInvalidPassphrasesBeforeEngineCall() {
    Engine engine = mock(Engine.class);
    KeyGenerationService service = new KeyGenerationService(
        engine, mock(Materials.class), mock(CredentialService.class), mock(Store.class));
    for (String password : new String[] {"密".repeat(171), "a\rb", "a\nb", "a\0b"}) {
      assertThrows(ApiError.class, () -> service.generate("project", "user",
          Map.of("algorithm", "SM2", "password", password)));
    }
    verifyNoInteractions(engine);
  }

  @Test
  void oneSecondBudgetCancelsSlowEngineResponse() throws Exception {
    var server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/internal/v1/key-generations", ex -> {
      try { Thread.sleep(2500); ex.sendResponseHeaders(200, -1); }
      catch (Exception ignored) {} finally { ex.close(); }
    });
    server.start();
    try {
      Engine engine = new Engine(new ObjectMapper(), "http://127.0.0.1:" + server.getAddress().getPort(), "fixture");
      KeyGenerationService service = new KeyGenerationService(
          engine, mock(Materials.class), mock(CredentialService.class), mock(Store.class));
      long start = System.nanoTime();
      assertThrows(ApiError.class, () -> service.generateWithTimeout("project", "user", Map.of("algorithm", "SM2"), 1));
      long elapsed = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      assertTrue(elapsed >= 800 && elapsed < 2200, "Engine call should expire at its one-second budget");
    } finally { server.stop(0); }
  }
}
