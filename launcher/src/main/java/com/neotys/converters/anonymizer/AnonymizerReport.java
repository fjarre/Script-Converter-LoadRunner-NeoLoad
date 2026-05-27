package com.neotys.converters.anonymizer;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Accumulates anonymization statistics (rule name → replacement count).
 * No sensitive values are stored — only counts, safe to log.
 */
public class AnonymizerReport {

    private final Map<String, Integer> counts = new LinkedHashMap<>();

    public void record(String ruleName, int count) {
        if (count > 0) {
            counts.merge(ruleName, count, Integer::sum);
        }
    }

    public int totalReplacements() {
        return counts.values().stream().mapToInt(Integer::intValue).sum();
    }

    public boolean hasReplacements() {
        return !counts.isEmpty();
    }

    public void printSummary() {
        if (counts.isEmpty()) {
            System.out.println("[anonymizer] No sensitive patterns detected.");
            return;
        }
        System.out.println("[anonymizer] Anonymisation summary:");
        counts.forEach((rule, count) ->
                System.out.printf("  %-35s %d replacement(s)%n", rule + ":", count));
        System.out.printf("  %-35s %d%n", "TOTAL:", totalReplacements());
    }

    /** Returns a copy of the counts map (rule → occurrences). */
    public Map<String, Integer> getCounts() {
        return Map.copyOf(counts);
    }
}
