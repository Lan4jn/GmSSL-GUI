package org.gmssl.gui.platform;

import java.util.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

public class ApiError extends RuntimeException {
  final int status;
  final String code;

  ApiError(int status, String code, String message) {
    super(message);
    this.status = status;
    this.code = code;
  }

  static ApiError bad(String message) {
    return new ApiError(400, "INVALID_REQUEST", message);
  }

  static ApiError denied() {
    return new ApiError(403, "FORBIDDEN", "Access denied");
  }

  static ApiError missing() {
    return new ApiError(404, "NOT_FOUND", "Resource not found");
  }
}

@RestControllerAdvice
class ErrorAdvice {
  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(ErrorAdvice.class);
  @ExceptionHandler(ApiError.class)
  ResponseEntity<?> api(ApiError e) {
    return ResponseEntity.status(e.status)
        .body(
            Map.of(
                "code",
                e.code,
                "message",
                e.getMessage(),
                "requestId",
                UUID.randomUUID().toString()));
  }

  @ExceptionHandler(Exception.class)
  ResponseEntity<?> other(Exception e) {
    int s =
        e instanceof org.springframework.web.multipart.MaxUploadSizeExceededException ? 413 : 500;
    String requestId = UUID.randomUUID().toString();
    if (s == 500) LOG.error("requestId={} status=500 diagnostics={}", requestId, safeDiagnostics(e));
    return ResponseEntity.status(s)
        .body(
            Map.of(
                "code",
                s == 413 ? "TOO_LARGE" : s == 400 ? "INVALID_REQUEST" : "INTERNAL_ERROR",
                "message",
                s == 413 ? "Upload too large" : s == 400 ? "Invalid request" : "Request failed",
                "requestId",
                requestId));
  }

  private static String safeDiagnostics(Throwable error) {
    StringBuilder out = new StringBuilder();
    Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
    for (int depth = 0; error != null && depth < 4 && seen.add(error); depth++, error = error.getCause()) {
      if (depth > 0) out.append(";cause ");
      out.append("type=").append(safeToken(error.getClass().getName()));
      if (error instanceof java.sql.SQLException sql) {
        String state = sql.getSQLState();
        out.append(" sqlState=").append(state != null && state.matches("[A-Z0-9]{5}") ? state : "UNKNOWN")
            .append(" vendorCode=").append(sql.getErrorCode());
      }
      StackTraceElement[] frames = error.getStackTrace();
      for (int i = 0; i < Math.min(frames.length, 5); i++) {
        StackTraceElement frame = frames[i];
        out.append(" at=").append(safeToken(frame.getClassName())).append('.').append(safeToken(frame.getMethodName()))
            .append('(').append(safeToken(frame.getFileName())).append(':').append(frame.getLineNumber()).append(')');
      }
    }
    return out.toString();
  }

  private static String safeToken(String token) {
    return token != null && token.length() <= 80 && token.matches("[A-Za-z0-9_.$<>-]+") ? token : "UNKNOWN";
  }

}
