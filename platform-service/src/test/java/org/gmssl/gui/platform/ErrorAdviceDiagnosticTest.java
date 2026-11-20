package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.sql.SQLException;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.slf4j.LoggerFactory;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

class ErrorAdviceDiagnosticTest {
  Logger logger;
  ListAppender<ILoggingEvent> capture;
  @BeforeEach void setup() {
    logger = (Logger) LoggerFactory.getLogger(ErrorAdvice.class);
    capture = new ListAppender<>(); capture.start(); logger.addAppender(capture);
  }
  @AfterEach void cleanup() { logger.detachAppender(capture); capture.stop(); }
  @Test void correlatesSafeSqlCauseWithoutMessagesOrThrowable() {
    String secret = "SECRET_SENTINEL jdbc:dm://private SQL SELECT password cookie PEM\nFORGED_EVENT";
    SQLException sql = new SQLException(secret, "42000", -6119);
    var response = new ErrorAdvice().other(new IllegalStateException(secret, sql));
    assertEquals(500, response.getStatusCode().value());
    var body = (Map<?, ?>)response.getBody();
    assertEquals("INTERNAL_ERROR", body.get("code"));
    assertEquals("Request failed", body.get("message"));
    assertEquals(1, capture.list.size());
    var event = capture.list.getFirst();
    String line = event.getFormattedMessage();
    assertTrue(line.contains(body.get("requestId").toString()));
    assertTrue(line.contains("status=500"));
    assertTrue(line.contains("java.lang.IllegalStateException"));
    assertTrue(line.contains("java.sql.SQLException"));
    assertTrue(line.contains("sqlState=42000"));
    assertTrue(line.contains("vendorCode=-6119"));
    assertFalse(line.contains("SECRET_SENTINEL"));
    assertFalse(line.contains("jdbc:"));
    assertFalse(line.contains("FORGED_EVENT"));
    assertFalse(line.contains("\n"));
    assertNull(event.getThrowableProxy());
    assertTrue(line.contains("ErrorAdviceDiagnosticTest"));
  }
  @Test void sanitizesMetadataAndBoundsFramesAndCauseCycle() {
    var sql = new SQLException("SECRET_SENTINEL", "bad\nSQLSTATE_SECRET", 7);
    var first = new RuntimeException("SECRET_SENTINEL");
    var second = new RuntimeException("SECRET_SENTINEL");
    first.initCause(second); second.initCause(first);
    StackTraceElement injected = new StackTraceElement("bad\nclass", "bad\rmethod", "bad\nfile", 1);
    StackTraceElement[] frames = new StackTraceElement[2000];
    java.util.Arrays.fill(frames, injected); sql.setStackTrace(frames);sql.initCause(first);
    new ErrorAdvice().other(sql);
    assertEquals(1, capture.list.size());
    String line = capture.list.getFirst().getFormattedMessage();
    assertTrue(line.length() <= 8192);
    assertFalse(line.contains("\n"));assertFalse(line.contains("\r"));
    assertFalse(line.contains("SECRET"));
    assertTrue(line.contains("sqlState=UNKNOWN"));
    assertNull(capture.list.getFirst().getThrowableProxy());
  }
  @Test void preservesUploadLimitAndAvoidsErrorSpamForExpectedRequests() {
    var response = new ErrorAdvice().other(new MaxUploadSizeExceededException(16));
    assertEquals(413, response.getStatusCode().value());
    var body = (Map<?, ?>)response.getBody();
    assertEquals("TOO_LARGE", body.get("code"));
    assertEquals("Upload too large", body.get("message"));
    new ErrorAdvice().api(ApiError.denied());
    assertTrue(capture.list.isEmpty());
  }
  @Test void causeDepthAndOutputRemainBounded() {
    Exception cause = new Exception("SECRET_SENTINEL");
    for(int i=0;i<100;i++) cause = new Exception("SECRET_SENTINEL",cause);
    new ErrorAdvice().other(cause);
    String line = capture.list.getFirst().getFormattedMessage();
    assertTrue(line.length() <= 8192);
    assertTrue(line.split("type=",-1).length <= 5);
    assertFalse(line.contains("SECRET_SENTINEL"));
    assertNull(capture.list.getFirst().getThrowableProxy());
  }
}
