package org.gmssl.gui.engine;

import java.net.InetAddress;
import java.net.URI;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class NetworkPolicy {
    private final EngineSettings settings;
    NetworkPolicy(EngineSettings settings) { this.settings = settings; }
    void validate(String command, Map<String,Object> parameters) {
        if (command.equals("crlget")) return;
        if (command.equals("ocspget")) {
            try {
                URI uri = URI.create(String.valueOf(parameters.getOrDefault("url", "")));
                validateUri(uri);
            } catch (IllegalArgumentException e) { throw EngineException.invalid(); }
        }
        if (command.endsWith("_server")) {
            listenPort(Integer.parseInt(String.valueOf(parameters.getOrDefault("port", 443))));
        } else if (command.endsWith("_client")) {
            host(String.valueOf(parameters.getOrDefault("host", "127.0.0.1")));
            outboundPort(Integer.parseInt(String.valueOf(parameters.getOrDefault("port", 443))));
        }
    }
    public void validateUri(URI uri) {
        if (uri == null || !"http".equals(uri.getScheme()) || uri.getUserInfo()!=null || uri.getFragment()!=null) throw new EngineException(400,"NETWORK_POLICY","Invalid URI scheme or authority");
        host(uri.getHost());
        outboundPort(uri.getPort() == -1 ? 80 : uri.getPort());
    }
    private void listenPort(int value) {
        if (value < 1024 || value > 65535 || !settings.allowedPorts.contains(value)) throw new EngineException(400,"NETWORK_POLICY","Network listen port not in deployment allowlist (must be >= 1024)");
    }
    private void outboundPort(int value) {
        if (value < 1 || value > 65535 || !settings.allowedPorts.contains(value)) throw new EngineException(400,"NETWORK_POLICY","Outbound network port not in deployment allowlist");
    }
    private void host(String value) {
        if (value == null || !value.matches("[0-9a-fA-F:.]+") || !settings.allowedHosts.contains(value)) throw new EngineException(400,"NETWORK_POLICY","Numeric target not in deployment allowlist");
        try {
            InetAddress address = InetAddress.getByName(value);
            byte[] bytes = address.getAddress();
            if (address.isAnyLocalAddress() || address.isLinkLocalAddress() || address.isMulticastAddress()
                    || (address.isLoopbackAddress() && !settings.allowLoopback)
                    || value.equals("255.255.255.255") || (bytes.length == 4 && (bytes[3] & 255) == 255))
                throw new EngineException(400,"NETWORK_POLICY","Target address class is blocked");
        } catch (java.net.UnknownHostException e) { throw EngineException.invalid(); }
    }
}
