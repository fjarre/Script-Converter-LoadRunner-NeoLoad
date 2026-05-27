package com.neotys.converters.anonymizer;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One anonymization rule: a regex pattern paired with a replacement string.
 * The replacement may reference capture groups via $1, $2, etc.
 */
record AnonymizerRule(String name, Pattern pattern, String replacement) {

    /**
     * Applies this rule to the input, returns the modified string and appends
     * the count of replacements to the provided array (index 0).
     */
    String apply(String input, int[] countOut) {
        Matcher m = pattern.matcher(input);
        StringBuilder sb = new StringBuilder();
        int count = 0;
        while (m.find()) {
            count++;
            m.appendReplacement(sb, replacement);
        }
        m.appendTail(sb);
        countOut[0] = count;
        return sb.toString();
    }
}
