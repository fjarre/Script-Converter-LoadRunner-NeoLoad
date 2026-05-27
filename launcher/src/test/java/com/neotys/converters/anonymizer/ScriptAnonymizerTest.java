package com.neotys.converters.anonymizer;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ScriptAnonymizerTest {

    @Rule
    public final TemporaryFolder tmp = new TemporaryFolder();

    // -------------------------------------------------------------------------
    // AnonymizerReport
    // -------------------------------------------------------------------------

    @Test
    public void report_empty_hasNoReplacements() {
        final AnonymizerReport report = new AnonymizerReport();
        Assert.assertFalse(report.hasReplacements());
        Assert.assertEquals(0, report.totalReplacements());
    }

    @Test
    public void report_accumulates_counts() {
        final AnonymizerReport report = new AnonymizerReport();
        report.record("rule-a", 2);
        report.record("rule-a", 1);
        report.record("rule-b", 3);
        Assert.assertTrue(report.hasReplacements());
        Assert.assertEquals(6, report.totalReplacements());
        Assert.assertEquals(3, (int) report.getCounts().get("rule-a"));
        Assert.assertEquals(3, (int) report.getCounts().get("rule-b"));
    }

    // -------------------------------------------------------------------------
    // ScriptAnonymizer — email rule
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_replaces_email_in_c_file() throws IOException {
        final Path sourceDir = createTempSource("test.c",
                "web_add_header(\"X-User\", \"john.doe@acme.ch\");");

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("test.c"), StandardCharsets.UTF_8);
        Assert.assertFalse("Email must be removed", result.contains("john.doe@acme.ch"));
        Assert.assertTrue("Placeholder must be present", result.contains("anon@example.com"));
        Assert.assertEquals(1, report.totalReplacements());
    }

    // -------------------------------------------------------------------------
    // LR web credentials
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_replaces_web_set_user_credentials() throws IOException {
        final Path sourceDir = createTempSource("script.c",
                "web_set_user(\"admin\", \"s3cr3t!\", \"realm\");");

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("script.c"), StandardCharsets.UTF_8);
        Assert.assertFalse("Username must be removed", result.contains("admin"));
        Assert.assertFalse("Password must be removed", result.contains("s3cr3t!"));
        Assert.assertTrue(result.contains("ANON_USER"));
        Assert.assertTrue(result.contains("ANON_PASS"));
        Assert.assertTrue(report.hasReplacements());
    }

    // -------------------------------------------------------------------------
    // LR lr_decrypt hardcoded
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_replaces_hardcoded_lr_decrypt() throws IOException {
        final Path sourceDir = createTempSource("script.c",
                "char *pwd = lr_decrypt(\"c4a3b2d1e5f6a7b8\");");

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("script.c"), StandardCharsets.UTF_8);
        Assert.assertFalse("Encoded password must be removed", result.contains("c4a3b2d1e5f6a7b8"));
        Assert.assertTrue(result.contains("ANON_ENCRYPTED"));
        Assert.assertTrue(report.hasReplacements());
    }

    @Test
    public void anonymize_keeps_parametric_lr_decrypt_intact() throws IOException {
        // lr_decrypt(lr_eval_string("{password}")) must NOT be touched
        final String original = "sapgui_logon(\"user\", lr_decrypt(lr_eval_string(\"{password}\")));";
        final Path sourceDir = createTempSource("script.c", original);

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("script.c"), StandardCharsets.UTF_8);
        Assert.assertTrue("Parametric lr_decrypt must remain", result.contains("lr_decrypt(lr_eval_string(\"{password}\"))"));
    }

    // -------------------------------------------------------------------------
    // URL embedded credentials
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_strips_url_credentials() throws IOException {
        // Note: '@' inside the password would cascade into the email rule — avoid it in this test.
        final Path sourceDir = createTempSource("script.c",
                "web_url(\"Login\", \"URL=https://apiuser:apiPass123@myapp.example.com/api\");");

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("script.c"), StandardCharsets.UTF_8);
        Assert.assertFalse("Username must be stripped", result.contains("apiuser"));
        Assert.assertFalse("Password must be stripped", result.contains("apiPass123"));
        Assert.assertTrue("Host must be preserved", result.contains("myapp.example.com"));
        Assert.assertTrue(result.contains("ANON_USER:ANON_PASS@"));
        Assert.assertTrue(report.hasReplacements());
    }

    // -------------------------------------------------------------------------
    // Credit card numbers
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_replaces_credit_card_in_dat_file() throws IOException {
        final Path sourceDir = createTempSource("carddata.dat",
                "card_number\n4111-1111-1111-1111\n4222 2222 2222 2222\n");

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("carddata.dat"), StandardCharsets.UTF_8);
        Assert.assertFalse("Real card number must be removed", result.contains("4111-1111-1111-1111"));
        Assert.assertFalse("Real card number must be removed", result.contains("4222 2222 2222 2222"));
        Assert.assertEquals(2, report.getCounts().get("credit-card-number").intValue());
    }

    // -------------------------------------------------------------------------
    // Swiss AHV
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_replaces_swiss_ahv() throws IOException {
        final Path sourceDir = createTempSource("user.dat",
                "ssn\n756.1234.5678.90\n");

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("user.dat"), StandardCharsets.UTF_8);
        Assert.assertFalse("AHV must be replaced", result.contains("756.1234.5678.90"));
        Assert.assertTrue(result.contains("756.0000.0000.00"));
    }

    // -------------------------------------------------------------------------
    // Non-sensitive file extensions not touched
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_skips_non_sensitive_extensions() throws IOException {
        final Path sourceDir = createTempSource("report.xml",
                "<email>john.doe@acme.ch</email>");

        final AnonymizerReport report = new AnonymizerReport();
        ScriptAnonymizer.anonymize(sourceDir, report);

        // XML files are not in the sensitive-extension list — no replacements expected
        Assert.assertFalse(report.hasReplacements());
    }

    // -------------------------------------------------------------------------
    // Original source directory must not be modified
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_does_not_modify_original_source() throws IOException {
        final String original = "web_set_user(\"admin\", \"secret\", \"realm\");";
        final Path sourceDir = createTempSource("script.c", original);

        final AnonymizerReport report = new AnonymizerReport();
        ScriptAnonymizer.anonymize(sourceDir, report);

        final String afterAnon = Files.readString(sourceDir.resolve("script.c"), StandardCharsets.UTF_8);
        Assert.assertEquals("Original file must not be modified", original, afterAnon);
    }

    // -------------------------------------------------------------------------
    // Multiple rules applied in one pass
    // -------------------------------------------------------------------------

    @Test
    public void anonymize_applies_multiple_rules_on_same_file() throws IOException {
        final Path sourceDir = createTempSource("mixed.c",
                "// author: john.doe@company.com\n"
                + "web_set_user(\"alice\", \"hunter2\", \"Basic\");\n"
                + "// card: 5500-0000-0000-0004\n");

        final AnonymizerReport report = new AnonymizerReport();
        final Path anonDir = ScriptAnonymizer.anonymize(sourceDir, report);

        final String result = Files.readString(anonDir.resolve("mixed.c"), StandardCharsets.UTF_8);
        Assert.assertFalse(result.contains("john.doe@company.com"));
        Assert.assertFalse(result.contains("alice"));
        Assert.assertFalse(result.contains("hunter2"));
        Assert.assertFalse(result.contains("5500-0000-0000-0004"));
        Assert.assertTrue("3 rules must have fired", report.totalReplacements() >= 3);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private Path createTempSource(final String fileName, final String content) throws IOException {
        final File dir = tmp.newFolder();
        final Path file = dir.toPath().resolve(fileName);
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return dir.toPath();
    }
}
