package mi.m4x.project.nekoshield;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.jar.JarFile;

/**
 * This is the main class for NekoShield, a security application designed to scan and detect malicious code signatures in JAR files.
 * The application works by walking through a specified directory and its subdirectories, examining each JAR file it encounters.
 * It uses a multi-threaded approach to scan multiple JAR files concurrently, improving performance on systems with multiple cores.
 * The scanning process is divided into two stages. In the first stage, it scans for known malicious code signatures. In the second stage, it performs additional checks for potential threats.
 * If a threat is detected, the application logs the path of the infected JAR file and the nature of the threat.
 * The application also provides functionality to cancel a running scan.
 *
 * @author Logan Abernathy (https://github.com/M4ximumPizza)
 */

public class NekoShield {

    private static ExecutorService executorService;

    public static void main(String[] args) {
        if (!checkArgs(args)) {
            return;
        }

        int nThreads = Integer.parseInt(args[0]);
        Path dirToCheck = Paths.get(args[1]);
        boolean emitWalkErrors = args.length > 2 && Boolean.parseBoolean(args[2]);

        Function<String, String> logOutput = outputString -> {
            System.out.println(outputString);
            return outputString;
        };

        logOutput.apply("NekoShield - Jar File Security Scanner");

        Results results = null;
        try {
            results = run(nThreads, dirToCheck, emitWalkErrors, logOutput);
        } catch (Exception e) {
            logOutput.apply("An error occurred during the scan: " + e.getMessage());
        }

        outputRunResults(results, logOutput);
    }

    public static void outputRunResults(Results results, Function<String, String> logOutput) {
        if (results == null) {
            logOutput.apply("Scan failed. Unable to display results.");
        } else {
            List<String> stage1Detections = results.getStage1Detections();
            List<String> stage2Detections = results.getStage2Detections();
            if (stage1Detections.isEmpty() && stage2Detections.isEmpty()) {
                logOutput.apply(Constants.ANSI_GREEN + "Scan complete. No infected jars found." + Constants.ANSI_RESET);
            } else {
                logOutput.apply(Constants.ANSI_RED + "Scan complete. Infections found!" + Constants.ANSI_RESET);
                outputInfectedFiles(stage1Detections, "Stage 1 Infections", logOutput);
                outputInfectedFiles(stage2Detections, "Stage 2 Infections", logOutput);
            }
        }
    }

    private static void outputInfectedFiles(List<String> infectedFiles, String stage, Function<String, String> logOutput) {
        if (!infectedFiles.isEmpty()) {
            logOutput.apply(Constants.ANSI_RED + stage + " (" + infectedFiles.size() + "):" + Constants.ANSI_RESET);
            for (int i = 0; i < infectedFiles.size(); i++) {
                logOutput.apply(Constants.ANSI_RED + "[" + (i + 1) + "] " + Constants.ANSI_WHITE + infectedFiles.get(i) + Constants.ANSI_RESET);
            }
        }
    }

    public static Results run(int nThreads, Path dirToCheck, boolean emitWalkErrors, Function<String, String> logOutput) {
        long startTime = System.currentTimeMillis();
        logOutput.apply(Constants.ANSI_GREEN + "Starting All Scans - " + Constants.ANSI_RESET
                + "This may take a while depending on the size of the directories and JAR files.");

        File dirToCheckFile = dirToCheck.toFile();
        if (!dirToCheckFile.exists() || !dirToCheckFile.isDirectory()) {
            throw new IllegalArgumentException("Specified directory is invalid: " + dirToCheck);
        }

        if (nThreads < 1) {
            throw new IllegalArgumentException("Number of threads must be at least 1");
        }

        executorService = Executors.newFixedThreadPool(nThreads);

        long stage1StartTime = System.currentTimeMillis();
        logOutput.apply(Constants.ANSI_GREEN + "Stage 1 Scan Starting" + Constants.ANSI_RESET);
        final List<String> stage1InfectionsList = new ArrayList<>();
        try {
            Files.walkFileTree(dirToCheck, new FileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    boolean isScannable = file.toString().toLowerCase().endsWith(Constants.JAR_FILE_EXTENSION);
                    if (isScannable) {
                        executorService.submit(() -> {
                            try (JarFile scannableJarFile = new JarFile(file.toFile())) {
                                boolean infectionDetected = Detector.scan(scannableJarFile, file, logOutput);
                                if (infectionDetected) {
                                    synchronized (stage1InfectionsList) {
                                        stage1InfectionsList.add(file.toString());
                                    }
                                }
                            } catch (Exception e) {
                                if (emitWalkErrors) {
                                    logOutput.apply("Failed to scan Jar file: " + file);
                                    e.printStackTrace();
                                }
                            }
                        });
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    if (emitWalkErrors) {
                        logOutput.apply("Failed to access file: " + file);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                    if (exc != null && emitWalkErrors) {
                        logOutput.apply("Failed to access directory: " + dir);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            throw new RuntimeException("An I/O error occurred while walking the directory tree", e);
        }

        executorService.shutdown();
        try {
            boolean timedOut = !executorService.awaitTermination(100000, TimeUnit.DAYS);
            if (timedOut) {
                logOutput.apply("Timed out while waiting for Jar scanning to complete.");
            }
        } catch (InterruptedException e) {
            logOutput.apply("Thread was interrupted while waiting for termination.");
            Thread.currentThread().interrupt(); // Preserve interrupted status
        }
        long stage1EndTime = System.currentTimeMillis();
        long stage1Time = stage1EndTime - stage1StartTime;
        logOutput.apply(Constants.ANSI_GREEN + "Stage 1 Finished - " + Constants.ANSI_RESET + "Took  " + stage1Time + "ms.");

        long stage2StartTime = System.currentTimeMillis();
        logOutput.apply(Constants.ANSI_GREEN + "Stage 2 Scan Starting" + Constants.ANSI_RESET);
        List<String> stage2InfectionsList = Detector.checkForStage2();
        long stage2EndTime = System.currentTimeMillis();
        long stage2Time = stage2EndTime - stage2StartTime;
        logOutput.apply(Constants.ANSI_GREEN + "Stage 2 Finished - " + Constants.ANSI_RESET + "Took  " + stage2Time + "ms.");

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        logOutput.apply(
                Constants.ANSI_GREEN + "All Scans Complete - " + Constants.ANSI_RESET + "Total " + totalTime + "ms.");

        return new Results(stage1InfectionsList, stage2InfectionsList);
    }

    public static void cancelScanIfRunning() {
        if (executorService != null) {
            executorService.shutdownNow();
        }
    }

    private static boolean checkArgs(String[] args) {
        if (args.length == 0) {
            mi.m4x.project.nekoguard.Gui.main(args);
            return false;
        }

        try {
            int nThreads = Integer.parseInt(args[0]);
            if (nThreads <= 0) {
                System.err.println("Thread count must be greater than 0.");
                return false;
            }
        } catch (NumberFormatException e) {
            System.err.println("Failed to parse thread count. Must be an integer.");
            return false;
        }

        File dirToCheck = new File(args[1]);
        if (!dirToCheck.exists() || !dirToCheck.isDirectory()) {
            System.err.println("Failed to find directory to scan. Does not exist or is not a directory.");
            return false;
        }

        return true;
    }
}
