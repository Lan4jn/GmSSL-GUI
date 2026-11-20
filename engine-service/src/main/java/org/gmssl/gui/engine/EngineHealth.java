package org.gmssl.gui.engine;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
public class EngineHealth implements HealthIndicator {
    private final ExecutionService executions;
    EngineHealth(ExecutionService executions){this.executions=executions;}
    @Override public Health health(){return executions.healthy()?Health.up().build():Health.down().build();}
}
