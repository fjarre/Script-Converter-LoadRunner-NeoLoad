package com.neotys.converters.launcher;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import com.neotys.converters.anonymizer.AnonymizerReport;
import com.neotys.converters.anonymizer.ScriptAnonymizer;
import com.neotys.neoload.model.ImmutableProject;
import com.neotys.neoload.model.Project;
import com.neotys.neoload.model.listener.CmdEventListener;
import com.neotys.neoload.model.readers.loadrunner.LoadRunnerReader;
import com.neotys.neoload.model.stats.ProjectType;
import com.neotys.neoload.model.writers.neoload.NeoLoadWriter;
import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import static com.neotys.neoload.model.writers.neoload.NeoLoadWriter.DEFAULT_PRODUCT_VERSION;
import static com.neotys.neoload.model.writers.neoload.NeoLoadWriter.DEFAULT_PROJECT_VERSION;

public class Launcher {

	private static final String PASSED = "Passed";
	private static final String MIGRATION_LOG_FOLDER = "migration_logs";
	private static final String UTF8_BOM = "﻿";
	private static final String PROJECT_VERSION_OPTION = "projectVersion";
	private static final String PRODUCT_VERSION_OPTION = "productVersion";

	/** Entry point — delegates to {@link #run} and exits with its return code. */
	public static void main(final String[] args) {
		System.exit(run(args));
	}

	/**
	 * Runs the converter and returns the process exit code:
	 * 0 = success / help printed, 1 = argument / IO error, 2 = migration failure.
	 */
	public static int run(final String[] args) {

		final Options options = getCmdLineOptions();

		if (Arrays.stream(args).anyMatch(Launcher::isHelpParameter)) {
			printHelp(options);
			return 0;
		}

		final CommandLine cmd;
		try {
			cmd = new DefaultParser().parse(options, args, false);
		} catch (MissingOptionException e) {
			System.err.println("The following required parameters is missing in the command line: "
					+ e.getMissingOptions().get(0).toString());
			printHelp(options);
			return 1;
		} catch (ParseException e) {
			System.err.println("Command line error:" + e.toString());
			printHelp(options);
			return 1;
		}

		final boolean zipConfig = !cmd.hasOption('d');
		final boolean anonymize = cmd.hasOption('a');

		final String sourceFolder = cmd.getOptionValue("source");
		final String destFolder = cmd.getOptionValue("target");
		final String projectName = cmd.getOptionValue("p");

		final String projectVersion = cmd.getOptionValue(PROJECT_VERSION_OPTION);
		final String productVersion = cmd.getOptionValue(PRODUCT_VERSION_OPTION);

		final String nlProjectFolder = destFolder + File.separator + projectName;
		try {
			createProjectDirectory(nlProjectFolder);
		} catch (final IOException ioe) {
			System.err.println("Error creating project directory: " + ioe.toString());
			return 1;
		}

		System.setProperty("logs.folder", nlProjectFolder + File.separator + MIGRATION_LOG_FOLDER);
		final Logger liveLogger = LoggerFactory.getLogger("LIVE");

		if (cmd.hasOption('l')) {
			ch.qos.logback.classic.Logger logger =
					(ch.qos.logback.classic.Logger) LoggerFactory.getLogger("FUNCTIONAL");
			final LoggerContext loggerContext = logger.getLoggerContext();
			ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<>();
			consoleAppender.setTarget("System.out");
			consoleAppender.setName("Console out");
			final PatternLayoutEncoder patternLayoutEncoder = new PatternLayoutEncoder() {
				@Override
				public byte[] encode(final ILoggingEvent event) {
					if (event.getLevel().isGreaterOrEqual(Level.WARN)) {
						return super.encode(event);
					}
					return new byte[0];
				}
			};
			patternLayoutEncoder.setPattern("%-5level - %msg%n");
			patternLayoutEncoder.setContext(loggerContext);
			patternLayoutEncoder.start();
			consoleAppender.setEncoder(patternLayoutEncoder);
			consoleAppender.setContext(loggerContext);
			consoleAppender.start();
			logger.addAppender(consoleAppender);
		}

		String additionalCustomActionMappingContent = "";
		if (cmd.hasOption('m')) {
			final String path = cmd.getOptionValue("m");
			try {
				additionalCustomActionMappingContent =
						new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
				if (additionalCustomActionMappingContent.startsWith(UTF8_BOM)) {
					additionalCustomActionMappingContent =
							additionalCustomActionMappingContent.substring(UTF8_BOM.length());
				} else {
					liveLogger.error("Error while reading file " + path
							+ ". Encoding is not UTF-8: "
							+ additionalCustomActionMappingContent.substring(0, 4));
					return 1;
				}
			} catch (final Exception exception) {
				liveLogger.error("Error while reading file " + path, exception);
				return 1;
			}
		}

		// Optionally pre-process source into an anonymized temp copy (GDPR)
		Path anonTempDir = null;
		final String effectiveSource;
		final AnonymizerReport anonReport;
		if (anonymize) {
			anonReport = new AnonymizerReport();
			try {
				anonTempDir = ScriptAnonymizer.anonymize(Paths.get(sourceFolder), anonReport);
				effectiveSource = anonTempDir.toString();
			} catch (final IOException ioe) {
				liveLogger.error("Anonymization failed, migration aborted.", ioe);
				return 1;
			}
		} else {
			anonReport = null;
			effectiveSource = sourceFolder;
		}

		final CmdEventListener cmdEventListener =
				new CmdEventListener(effectiveSource, destFolder, projectName);
		String status = PASSED;
		final boolean passed;
		try {
			final LoadRunnerReader lrReader = new LoadRunnerReader(
					cmdEventListener, effectiveSource, projectName, additionalCustomActionMappingContent);
			final Project project = lrReader.read();
			final NeoLoadWriter nlWriter = new NeoLoadWriter(
					ImmutableProject.copyOf(project).withName(projectName),
					nlProjectFolder, lrReader.getFileToCopy());
			nlWriter.write(zipConfig, projectVersion, productVersion);
		} catch (final IllegalArgumentException | IllegalStateException e) {
			liveLogger.error("Error during project migration, migration aborted.", e);
			status = "Failed: " + e.getMessage();
		} finally {
			passed = PASSED.equals(status);
			if (passed) {
				cmdEventListener.printSummary();
				if (anonReport != null) {
					anonReport.printSummary();
				}
			}
			if (cmd.hasOption('r')) {
				cmdEventListener.generateJsonReport(ProjectType.LOAD_RUNNER, status);
			}
			if (anonTempDir != null) {
				deleteQuietly(anonTempDir);
			}
		}
		return passed ? 0 : 2;
	}

	private static void printHelp(final Options options) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp("script-converter", options, true);
	}

	private static Options getCmdLineOptions() {
		final Options options = new Options();
		options.addOption("h", "help", false, "print this message");
		options.addRequiredOption("s", "source", true, "The source directory of the project to migrate.");
		options.addRequiredOption("t", "target", true, "The target folder where the generated project will be written.");
		options.addRequiredOption("p", "project", true, "The name of the converted project.");
		options.addOption("l", "log", false, "More information is displayed on stdout.");
		options.addOption("r", "report", false, "A JSON report containing key statistics is generated.");
		options.addOption("d", "debug", false, "Store project as XML format for debugging purpose.");
		options.addOption("m", "mapping", true,
				"Add additional custom action mapping rule from YAML file with UTF-8 charset.");
		options.addOption("a", "anonymize", false,
				"Pre-process source scripts to remove GDPR-sensitive data (credentials, emails, PII) "
				+ "before conversion. Operates on a temporary copy — original files are never modified.");
		options.addOption(PROJECT_VERSION_OPTION, true,
				"The NeoLoad project version stored in the NLP file. By default it is: "
				+ DEFAULT_PROJECT_VERSION + ".");
		options.addOption(PRODUCT_VERSION_OPTION, true,
				"The NeoLoad product version stored in the NLP file. By default it is: "
				+ DEFAULT_PRODUCT_VERSION + ".");
		return options;
	}

	private static boolean isHelpParameter(final String param) {
		return "-h".equals(param) || "--help".equals(param);
	}

	private static void deleteQuietly(final Path dir) {
		try {
			Files.walk(dir)
					.sorted(java.util.Comparator.reverseOrder())
					.map(Path::toFile)
					.forEach(java.io.File::delete);
		} catch (IOException e) {
			LoggerFactory.getLogger(Launcher.class).warn("Could not delete temp directory: {}", dir);
		}
	}

	private static void createProjectDirectory(final String nlProjectFolder) throws IOException {
		final File f = new File(nlProjectFolder);
		if (!f.exists()) {
			Files.createDirectories(Paths.get(nlProjectFolder));
		} else if (f.isFile()) {
			throw new IOException("The destination is not a directory, migration aborted.");
		}
		final File logsFolder = new File(nlProjectFolder, MIGRATION_LOG_FOLDER);
		logsFolder.mkdir();
	}
}
