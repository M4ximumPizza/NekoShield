package mi.m4x.project.nekoshield;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.*;

import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.jar.JarFile;
import java.util.Objects;

import static org.objectweb.asm.Opcodes.*;

/**
 * This is the main class for NekoShield, a security application designed to scan and detect malicious code signatures in JAR files.
 *
 * @author Logan Abernathy (https://github.com/M4ximumPizza)
 */
public class Detector {

    /**
     * Scans for malicious code signatures in the specified {@link JarFile} located at the specified {@link Path}.
     *
     * @param file   The {@link JarFile} to scan.
     * @param path   The {@link Path} of the {@link JarFile} to scan.
     * @param output The function to output messages.
     * @return {@code true} if a signature match was found, otherwise {@code false}.
     */
    public static boolean scan(JarFile file, Path path, Function<String, String> output) {
        boolean signatureMatchFound = false;

        try {
            signatureMatchFound = file.stream()
                    .filter(entry -> entry.getName().endsWith(Constants.CLASS_FILE_EXTENSION))
                    .anyMatch(entry -> {
                        try {
                            return scanClass(getByteArray(file.getInputStream(entry)));
                        } catch (IOException e) {
                            output.apply("Failed to scan class in Jar file [" + path + "] due to an IO error: " + entry.getName());
                            output.apply("Error:" + e.getMessage());
                            return false;
                        } catch (IllegalArgumentException e) {
                            output.apply("Failed to scan class in Jar file [" + path + "] due to a parsing error: " + entry.getName());
                            output.apply("This is likely due to a malformed class file or an issue with the JAR file itself.");
                            output.apply("Error:" + e.getMessage());
                            return false;
                        }
                    });
        } catch (Exception e) {
            output.apply("Failed to scan Jar file: " + path);
            output.apply("Error:" + e.getMessage());
        } finally {
            try {
                file.close();
            } catch (IOException e) {
                output.apply("Failed to close Jar file after scan: " + path);
                output.apply("Error:" + e.getMessage());
            }
        }

        return signatureMatchFound;
    }

    private static byte[] getByteArray(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[16384];
        int nRead;
        while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }

    private static final AbstractInsnNode[] SIG1 = new AbstractInsnNode[]{
            new TypeInsnNode(NEW, "java/lang/String"),
            new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V"),
            new TypeInsnNode(NEW, "java/lang/String"),
            new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V"),
            new MethodInsnNode(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;"),
            new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getConstructor", "([Ljava/lang/Class;)" +
                    "Ljava/lang/reflect/Constructor;"),
            new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V"),
            new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V"),
            new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V"),
            new MethodInsnNode(INVOKESPECIAL, "java/net/URL", "<init>",
                    "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V"),
            new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Constructor", "newInstance",
                    "([Ljava/lang/Object;)Ljava/lang/Object;"),
            new MethodInsnNode(INVOKESTATIC, "java/lang/Class", "forName",
                    "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;"),
            new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V"),
            new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                    "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;"),
            new MethodInsnNode(INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                    "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"),
    };

    private static final AbstractInsnNode[] SIG2 = new AbstractInsnNode[]{
            new MethodInsnNode(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;"),
            new MethodInsnNode(INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64$Decoder;"),
            new MethodInsnNode(INVOKEVIRTUAL, "java/lang/String", "concat",
                    "(Ljava/lang/String;)Ljava/lang/String;"), // TODO:FIXME: this might not be in all of them
            new MethodInsnNode(INVOKEVIRTUAL, "java/util/Base64$Decoder", "decode", "(Ljava/lang/String;)[B"),
            new MethodInsnNode(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V"),
            new MethodInsnNode(INVOKEVIRTUAL, "java/io/File", "getPath", "()Ljava/lang/String;"),
            new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;"),
    };

    private static final AbstractInsnNode[] SIG3 = new AbstractInsnNode[]{
            new IntInsnNode(BIPUSH, 56),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new InsnNode(ICONST_1),
            new IntInsnNode(BIPUSH, 53),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new InsnNode(ICONST_2),
            new IntInsnNode(BIPUSH, 46),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new InsnNode(ICONST_3),
            new IntInsnNode(BIPUSH, 50),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new InsnNode(ICONST_4),
            new IntInsnNode(BIPUSH, 49),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new InsnNode(ICONST_5),
            new IntInsnNode(BIPUSH, 55),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 6),
            new IntInsnNode(BIPUSH, 46),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 7),
            new IntInsnNode(BIPUSH, 49),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 8),
            new IntInsnNode(BIPUSH, 52),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 9),
            new IntInsnNode(BIPUSH, 52),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 10),
            new IntInsnNode(BIPUSH, 46),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 11),
            new IntInsnNode(BIPUSH, 49),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 12),
            new IntInsnNode(BIPUSH, 51),
            new InsnNode(BASTORE),
            new InsnNode(DUP),
            new IntInsnNode(BIPUSH, 13),
            new IntInsnNode(BIPUSH, 48)
    };

    private static boolean same(AbstractInsnNode a, AbstractInsnNode b) {
        if (a instanceof TypeInsnNode) {
            TypeInsnNode aa = (TypeInsnNode) a;
            return aa.desc.equals(((TypeInsnNode) b).desc);
        }
        if (a instanceof MethodInsnNode) {
            MethodInsnNode aa = (MethodInsnNode) a;
            return aa.owner.equals(((MethodInsnNode) b).owner)
                    && aa.name.equals(((MethodInsnNode) b).name)
                    && aa.desc.equals(((MethodInsnNode) b).desc);
        }
        return a instanceof InsnNode;
    }

    public static boolean scanClass(byte[] clazz) {
        ClassReader reader = new ClassReader(clazz);
        ClassNode node = new ClassNode();
        try {
            reader.accept(node, 0);
        } catch (Exception e) {
            return false;
        }
        for (MethodNode method : node.methods) {
            boolean match = checkMethodForSignature(method, SIG1) || checkMethodForSignature(method, SIG2) ||
                    checkMethodForSignature(method, SIG3);
            if (match) {
                return true;
            }
        }
        return false;
    }

    private static boolean checkMethodForSignature(MethodNode method, AbstractInsnNode[] signature) {
        int signatureIndex = 0;
        for (int i = 0; i < method.instructions.size(); i++) {
            AbstractInsnNode insn = method.instructions.get(i);
            if (insn.getOpcode() == -1) {
                continue;
            }
            if (insn.getOpcode() == signature[signatureIndex].getOpcode()) {
                if (same(insn, signature[signatureIndex])) {
                    signatureIndex++;
                    if (signatureIndex == signature.length) {
                        return true;
                    }
                }
            } else {
                signatureIndex = 0;
            }
        }
        return false;
    }

    public static List<String> checkForStage2() {
        List<String> suspiciousFilesFound = new ArrayList<>();

        Path windowsStartupDirectory = (Objects.isNull(System.getenv("APPDATA"))
                ? Paths.get(System.getProperty("user.home"), "AppData", "Roaming")
                : Paths.get(System.getenv("APPDATA")))
                .resolve(Paths.get("Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        boolean windows = Files.isDirectory(windowsStartupDirectory) && Files.isWritable(windowsStartupDirectory);

        String[] maliciousFiles = {".ref", "client.jar", "lib.dll", "libWebGL64.jar", "run.bat"};

        if (windows) {
            File edgeFolder = new File(System.getenv("APPDATA") + "\\Microsoft Edge");
            if (edgeFolder.exists()) {
                suspiciousFilesFound.add(edgeFolder.getAbsolutePath());
            }

            File startFolder = new File(System.getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            if (startFolder.exists() && startFolder.isDirectory()) {
                File[] startFiles = startFolder.listFiles();
                if (startFiles != null) {
                    for (File startFile : startFiles) {
                        for (String maliciousFile : maliciousFiles) {
                            if (startFile.getName().equals(maliciousFile)) {
                                suspiciousFilesFound.add(startFile.getAbsolutePath());
                            }
                        }
                    }
                }
            }
        }

        if (System.getProperty("os.name").toLowerCase().contains("linux")) {
            File file = new File("~/.config/.data/lib.jar");
            if (file.exists()) {
                suspiciousFilesFound.add(file.getAbsolutePath());
            }
        }

        return suspiciousFilesFound;
    }
}
