package global.gua.resolver.roster.store;

import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.jdbc.datasource.init.ScriptUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The H2 test schema is mirrored by hand from the Flyway migrations, which is the likeliest source of a
 * test-versus-production divergence (brief risk 10). This applies the real migrations to one database, the
 * hand-written mirror to another, and compares the resulting columns.
 */
class SchemaParityTest {

    @Test
    void theHandMirroredTestSchemaMatchesTheFlywayMigrations() throws Exception {
        DataSource migrated = database("parity-flyway");
        Flyway.configure().dataSource(migrated).locations("classpath:db/migration").load().migrate();

        DataSource mirrored = database("parity-script");
        try (Connection c = mirrored.getConnection()) {
            ScriptUtils.executeSqlScript(c, new ClassPathResource("schema.sql"));
        }

        assertThat(columns(mirrored)).isEqualTo(columns(migrated));
    }

    private static DataSource database(String name) {
        return new SimpleDriverDataSource(new org.h2.Driver(),
                "jdbc:h2:mem:" + name + "-" + System.nanoTime() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa", "");
    }

    /** table.column to type and nullability, for every table except Flyway's own bookkeeping. */
    private static Map<String, String> columns(DataSource ds) {
        Map<String, String> columns = new LinkedHashMap<>();
        new JdbcTemplate(ds).query("""
                SELECT table_name, column_name, data_type, character_maximum_length, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'PUBLIC' AND UPPER(table_name) <> 'FLYWAY_SCHEMA_HISTORY'
                ORDER BY table_name, column_name
                """, rs -> {
            columns.put(rs.getString("table_name") + "." + rs.getString("column_name"),
                    rs.getString("data_type") + "(" + rs.getString("character_maximum_length") + ") "
                            + rs.getString("is_nullable"));
        });
        return columns;
    }
}
