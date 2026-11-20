package org.gmssl.gui.engine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class EngineSecurity extends OncePerRequestFilter {
    private final byte[] tokenDigest;
    private final int maxRequest;
    EngineSecurity(EngineSettings settings) { tokenDigest = digest(settings.token); maxRequest = settings.maxBytes * 3; }
    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new IllegalStateException("Digest unavailable"); }
    }
    @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        if (req.getRequestURI().equals("/actuator/health")) { chain.doFilter(req,res); return; }
        String value = req.getHeader("X-Engine-Token");
        if (value == null || value.length() > 4096 || !MessageDigest.isEqual(tokenDigest, digest(value))) {
            res.setStatus(401); res.setContentType("application/json"); res.getWriter().write("{\"code\":\"UNAUTHENTICATED\",\"message\":\"Authentication required\",\"requestId\":\"\"}"); return;
        }
        if (req.getContentLengthLong() > maxRequest) { res.sendError(413); return; }
        chain.doFilter(new jakarta.servlet.http.HttpServletRequestWrapper(req) {
            @Override public jakarta.servlet.ServletInputStream getInputStream() throws IOException {
                var stream = super.getInputStream();
                return new jakarta.servlet.ServletInputStream() {
                    int count;
                    @Override public int read() throws IOException { int b = stream.read(); if (b >= 0 && ++count > maxRequest) throw new IOException("Request size limit exceeded"); return b; }
                    @Override public boolean isFinished() { return stream.isFinished(); }
                    @Override public boolean isReady() { return stream.isReady(); }
                    @Override public void setReadListener(jakarta.servlet.ReadListener l) { stream.setReadListener(l); }
                };
            }
        },res);
    }
}
