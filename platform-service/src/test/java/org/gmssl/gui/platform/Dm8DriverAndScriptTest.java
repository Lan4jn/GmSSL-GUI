package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Driver;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Dm8DriverAndScriptTest {

  @Test
  void testDmDriverClassLoadableAndRegistered() throws Exception {
    Class<?> driverClass = Class.forName("dm.jdbc.driver.DmDriver");
    assertNotNull(driverClass, "DmDriver class must be present on classpath");
    assertTrue(Driver.class.isAssignableFrom(driverClass), "DmDriver must implement java.sql.Driver");

    Driver driver = (Driver) driverClass.getDeclaredConstructor().newInstance();
    assertNotNull(driver);
    assertTrue(driver.jdbcCompliant());
  }

  @Test
  void testDmInitSchemaSqlFilePresentAndSyntacticallyValid() throws Exception {
    InputStream in = getClass().getResourceAsStream("/db/dm/init_schema_dm8.sql");
    assertNotNull(in, "init_schema_dm8.sql must be packaged in classpath resources under /db/dm/");
    String sql = new String(in.readAllBytes(), StandardCharsets.UTF_8);

    // Verify all 9 expected tables and index are defined
    List<String> requiredTables = List.of(
        "app_users",
        "sessions",
        "projects",
        "memberships",
        "materials",
        "jobs",
        "artifacts",
        "audit_events",
        "stateful_material_history",
        "stateful_promotions",
        "key_credentials"
    );

    for (String table : requiredTables) {
      assertTrue(sql.contains("CREATE TABLE " + table), "SQL script must define table: " + table);
    }
    assertTrue(sql.contains("CREATE INDEX audit_project"), "SQL script must define audit_project index");
    assertTrue(sql.contains("VARBINARY(4096)"), "key_credentials encrypted_passphrase must use VARBINARY(4096)");
    assertTrue(sql.contains("BIT"), "materials and jobs must use BIT type for DM8 boolean representation");
  }

  @Test
  void testApplicationDmYmlValidAndDisablesFlyway() throws Exception {
    InputStream in = getClass().getResourceAsStream("/application-dm.yml");
    assertNotNull(in, "application-dm.yml must be present on classpath");
    String yml = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(yml.contains("dm.jdbc.driver.DmDriver"));
    assertTrue(yml.contains("flyway:"));
    assertTrue(yml.contains("enabled: false"));
  }
  @Test
  void testStoreBoolStrictMapping() {
    // 1. Boolean instances
    assertTrue(Store.bool(Map.of("k", true), "k"));
    assertFalse(Store.bool(Map.of("k", false), "k"));

    // 2. Non-Boolean objects (numbers, strings, etc.) must remain false (no loose type coercion)
    assertFalse(Store.bool(Map.of("k", 1), "k"));
    assertFalse(Store.bool(Map.of("k", 1L), "k"));
    assertFalse(Store.bool(Map.of("k", "true"), "k"));
    assertFalse(Store.bool(Map.of("k", "1"), "k"));
    assertFalse(Store.bool(Map.of("k", 0), "k"));

    // 3. Null and missing keys
    assertFalse(Store.bool(Collections.singletonMap("k", null), "k"));
    assertFalse(Store.bool(Map.of(), "missing"));
  }
}
