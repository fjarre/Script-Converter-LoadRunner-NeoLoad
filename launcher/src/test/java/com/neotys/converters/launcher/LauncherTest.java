package com.neotys.converters.launcher;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Files;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class LauncherTest {

	private static final File TARGET_DIR = Files.createTempDir();

	@Test
	public void mainTestHelp() {
		assertEquals(0, Launcher.run(ImmutableList.of("--help").toArray(new String[0])));
	}

	@Test
	public void mainTestH() {
		assertEquals(0, Launcher.run(ImmutableList.of("-h").toArray(new String[0])));
	}

	@Test
	public void mainTestInvalid() {
		assertEquals(1, Launcher.run("-p test".split(" ")));
	}

	@Test
	public void mainTestNoLrProjectWithLogs() {
		final File sourceDir = Files.createTempDir();
		final String args = "-l -s " + sourceDir.getAbsolutePath() + " -t " + TARGET_DIR.getAbsolutePath() + " -p project";
		assertEquals(2, Launcher.run(args.split(" ")));
	}

	@Test
	public void mainTestInvalidCustomMapping() throws IOException {
		final File sourceDir = Files.createTempDir();
		final File tempFile = File.createTempFile("pre", "suf");
		final String args = "-d -m" + tempFile.getAbsolutePath() + " -s " + sourceDir.getAbsolutePath() + " -t " + TARGET_DIR.getAbsolutePath() + " -p project";
		assertEquals(1, Launcher.run(args.split(" ")));
	}

	@Test
	public void mainTestInvalidSourceFolder() {
		final String args = "-s mysource -t " + TARGET_DIR.getAbsolutePath() + " -p test";
		assertEquals(2, Launcher.run(args.split(" ")));
	}

	@Test
	public void mainTestNoSourceFolder() {
		final String args = "-s -t " + TARGET_DIR.getAbsolutePath() + " -p test";
		assertEquals(1, Launcher.run(args.split(" ")));
	}

	@Test
	public void mainTestInvalidProjectFile() {
		assertEquals(1, Launcher.run("-s mySource -t src/test/resources/projects -p test".split(" ")));
	}

	@Test
	public void mainTestInvalidEmptySourceFolder() {
		final File myTempDir = Files.createTempDir();
		final String args = "-s " + myTempDir + " -t " + TARGET_DIR.getAbsolutePath() + " -p test";
		assertEquals(2, Launcher.run(args.split(" ")));
	}
}
