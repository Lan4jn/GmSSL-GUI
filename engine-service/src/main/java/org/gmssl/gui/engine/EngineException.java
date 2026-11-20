package org.gmssl.gui.engine;

public class EngineException extends RuntimeException {
    final int status;
    final String code;
    EngineException(int status, String code, String message) { super(message); this.status=status; this.code=code; }
    static EngineException invalid() { return new EngineException(400,"INVALID_PARAMETERS","Parameters do not satisfy the tool contract"); }
}
