package com.neotys.converters.anonymizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Pre-processes LoadRunner script directories to remove GDPR-sensitive data
 * before conversion. Operates on a temporary copy — the original source is
 * never modified.
 *
 * Rules (applied in order, most-specific first):
 *   1. LR web credentials   web_set_user("user","pass",...)
 *   2. LR encrypted secrets  lr_decrypt("hardcoded_value")
 *   3. URL embedded creds    http://user:pass@host
 *   4. Email addresses       user@domain.tld
 *   5. Credit card numbers   DDDD-DDDD-DDDD-DDDD
 *   6. Swiss AHV numbers     756.XXXX.XXXX.XX
 *   7. EU/CH phone numbers   +41 / +33 / +49 … prefixes
 */
public class ScriptAnonymizer {

    private static final Logger log = LoggerFactory.getLogger(ScriptAnonymizer.class);

    private static final List<String> SENSITIVE_EXTENSIONS =
            List.of(".c", ".prm", ".dat", ".usr", ".cfg");

    // Regex flags: CASE_INSENSITIVE where appropriate, MULTILINE everywhere
    private static final List<AnonymizerRule> RULES = List.of(

        // LR HTTP credentials: web_set_user("username", "password", "realm")
        new AnonymizerRule(
            "lr-web-credentials",
            Pattern.compile("web_set_user\\s*\\(\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\""),
            "web_set_user(\"ANON_USER\", \"ANON_PASS\""
        ),

        // LR encrypted password with hardcoded value (not a parameter reference)
        // Matches: lr_decrypt("c5f3d1a2...") but not lr_decrypt(lr_eval_string("{p}"))
        new AnonymizerRule(
            "lr-decrypt-hardcoded",
            Pattern.compile("lr_decrypt\\(\"([^\"\\{]{8,})\"\\)"),
            "lr_decrypt(\"ANON_ENCRYPTED\")"
        ),

        // URL with embedded credentials: http://user:pass@host or https://user:pass@host
        new AnonymizerRule(
            "url-embedded-credentials",
            Pattern.compile("(https?://)([^:@/\"\\s]+):([^@\"\\s]+)@"),
            "$1ANON_USER:ANON_PASS@"
        ),

        // Email addresses — (?<!:) avoids re-matching password part of already-anonymized URLs
        // (e.g. https://ANON_USER:ANON_PASS@host where ANON_PASS@host would otherwise match)
        new AnonymizerRule(
            "email-address",
            Pattern.compile("(?<!:)\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b"),
            "anon@example.com"
        ),

        // Credit/debit card numbers (4 groups of 4 digits, space or dash separator)
        new AnonymizerRule(
            "credit-card-number",
            Pattern.compile("\\b\\d{4}[\\s\\-]\\d{4}[\\s\\-]\\d{4}[\\s\\-]\\d{4}\\b"),
            "0000-0000-0000-0000"
        ),

        // Swiss AHV / social security: 756.XXXX.XXXX.XX
        new AnonymizerRule(
            "swiss-ahv-number",
            Pattern.compile("\\b756\\.\\d{4}\\.\\d{4}\\.\\d{2}\\b"),
            "756.0000.0000.00"
        ),

        // European phone numbers with country prefix (+41, +33, +49, +32, +44)
        new AnonymizerRule(
            "eu-phone-number",
            Pattern.compile("\\b(\\+41|\\+33|\\+49|\\+32|\\+44|0041|0033|0049)\\s?[\\d\\s\\.\\-]{7,15}\\b"),
            "ANON_PHONE"
        )
    );

    /**
     * Creates an anonymized copy of {@code sourceDir} in a temporary directory.
     *
     * @param sourceDir original LoadRunner script directory (read-only)
     * @param report    accumulates replacement statistics
     * @return path to the anonymized temporary directory (caller must delete after use)
     */
    public static Path anonymize(Path sourceDir, AnonymizerReport report) throws IOException {
        final Path tempDir = Files.createTempDirectory("script-converter-anon-");
        log.info("[anonymizer] Copying source to temp directory: {}", tempDir);
        copyDirectory(sourceDir, tempDir);
        log.info("[anonymizer] Scanning for sensitive patterns...");
        processDirectory(tempDir, report);
        return tempDir;
    }

    // -------------------------------------------------------------------------

    private static void copyDirectory(Path source, Path target) throws IOException {
        Files.walkFileTree(source, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                Files.createDirectories(target.resolve(source.relativize(dir)));
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.copy(file, target.resolve(source.relativize(file)),
                        StandardCopyOption.REPLACE_EXISTING);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void processDirectory(Path dir, AnonymizerReport report) throws IOException {
        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                String name = file.getFileName().toString().toLowerCase();
                boolean sensitive = SENSITIVE_EXTENSIONS.stream().anyMatch(name::endsWith);
                if (sensitive) {
                    processFile(file, report);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                log.warn("[anonymizer] Could not read file: {} — {}", file, exc.getMessage());
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void processFile(Path file, AnonymizerReport report) throws IOException {
        final String original = Files.readString(file, StandardCharsets.UTF_8);
        String current = original;
        final int[] countBuf = new int[1];

        for (AnonymizerRule rule : RULES) {
            String after = rule.apply(current, countBuf);
            if (countBuf[0] > 0) {
                report.record(rule.name(), countBuf[0]);
                log.debug("[anonymizer] {} → rule '{}': {} replacement(s) in {}",
                        file.getFileName(), rule.name(), countBuf[0], file.getFileName());
                current = after;
            }
        }

        if (!current.equals(original)) {
            Files.writeString(file, current, StandardCharsets.UTF_8);
        }
    }
}
