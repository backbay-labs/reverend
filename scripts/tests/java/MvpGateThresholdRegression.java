import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class MvpGateThresholdRegression {
    private static final Map<String, String> EXPECTED_OPERATORS = new LinkedHashMap<>();
    private static final Map<String, String> EXPECTED_THRESHOLDS = new LinkedHashMap<>();

    static {
        EXPECTED_OPERATORS.put("recall_at_10_delta_vs_stock", ">=");
        EXPECTED_OPERATORS.put("search_latency_p95_ms", "<=");
        EXPECTED_OPERATORS.put("receipt_completeness", "==");
        EXPECTED_OPERATORS.put("rollback_success_rate", "==");

        EXPECTED_THRESHOLDS.put("recall_at_10_delta_vs_stock", "0.1");
        EXPECTED_THRESHOLDS.put("search_latency_p95_ms", "300.0");
        EXPECTED_THRESHOLDS.put("receipt_completeness", "1.0");
        EXPECTED_THRESHOLDS.put("rollback_success_rate", "1.0");
    }

    private MvpGateThresholdRegression() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: MvpGateThresholdRegression <thresholds-json-path>");
        }

        Path thresholdsPath = Path.of(args[0]);
        if (!Files.exists(thresholdsPath)) {
            throw new IllegalStateException("thresholds file does not exist: " + thresholdsPath);
        }

        String compact = Files.readString(thresholdsPath, StandardCharsets.UTF_8).replaceAll("\\s+", "");
        if (!compact.contains("\"gates\":{")) {
            throw new IllegalStateException("threshold config missing top-level gates object");
        }

        for (String metric : EXPECTED_OPERATORS.keySet()) {
            String metricBlock = extractMetricBlock(compact, metric);

            String expectedOperator = EXPECTED_OPERATORS.get(metric);
            String expectedThreshold = EXPECTED_THRESHOLDS.get(metric);
            if (!metricBlock.contains("\"operator\":\"" + expectedOperator + "\"")) {
                throw new IllegalStateException("metric '" + metric + "' missing operator '" + expectedOperator + "'");
            }
            if (!metricBlock.contains("\"threshold\":" + expectedThreshold)) {
                throw new IllegalStateException("metric '" + metric + "' missing threshold " + expectedThreshold);
            }
            if (!metricBlock.contains("\"severity\":\"")) {
                throw new IllegalStateException("metric '" + metric + "' missing severity");
            }
            if (!metricBlock.contains("\"action\":\"")) {
                throw new IllegalStateException("metric '" + metric + "' missing remediation action");
            }
        }

        System.out.println("[java-gate] threshold contract OK for 4 MVP release gates");
    }

    private static String extractMetricBlock(String compactJson, String metricName) {
        String marker = "\"" + metricName + "\":{";
        int markerIndex = compactJson.indexOf(marker);
        if (markerIndex < 0) {
            throw new IllegalStateException("missing metric '" + metricName + "' in threshold config");
        }

        int blockStart = markerIndex + marker.length() - 1;
        int depth = 0;
        for (int index = blockStart; index < compactJson.length(); index++) {
            char token = compactJson.charAt(index);
            if (token == '{') {
                depth += 1;
            } else if (token == '}') {
                depth -= 1;
                if (depth == 0) {
                    return compactJson.substring(blockStart, index + 1);
                }
            }
        }

        throw new IllegalStateException("unable to parse metric block for '" + metricName + "'");
    }
}
