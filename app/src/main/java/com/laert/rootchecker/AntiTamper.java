package com.laert.rootchecker;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class AntiTamper {

    private static final String EXPECTED_SIGNATURE =
            "177D0B6AC00A4D5DD3FE8269EC86951FCFFA134EAD8CBB13B6AE227AD03B4078";

    public static class TamperResult {

        public final String name;
        public final String detail;
        public final boolean detected;

        public TamperResult(String name,
                            String detail,
                            boolean detected) {

            this.name = name;
            this.detail = detail;
            this.detected = detected;
        }
    }

    public TamperResult[] runAllChecks(Context ctx) {

        List<TamperResult> results = new ArrayList<>();

        results.add(checkXposedInProcess());
        results.add(checkFridaInProcess());
        results.add(checkSuspiciousLibraries());
        results.add(checkStackTrace());
        results.add(checkAppSignature(ctx));
        results.add(checkPackageName(ctx));
        results.add(checkDebugger());
        results.add(checkEmulatorProcess());
        results.add(checkHookingFrameworks());
        results.add(checkFridaPorts());
        results.add(checkLSPatch());
        results.add(checkManifestIntegrity(ctx));
        results.add(checkClassLoader());
        results.add(checkAppComponentFactory(ctx));
        results.add(checkVirtualEnvironment(ctx));

        return results.toArray(new TamperResult[0]);
    }

    private TamperResult checkAppSignature(Context ctx) {

        try {

            PackageManager pm = ctx.getPackageManager();

            PackageInfo packageInfo;

            Signature[] signatures;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {

                packageInfo = pm.getPackageInfo(
                        ctx.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES
                );

                SigningInfo signingInfo = packageInfo.signingInfo;

                if (signingInfo == null) {
                    return new TamperResult(
                            "APK Signature",
                            "SigningInfo is null",
                            true
                    );
                }

                if (signingInfo.hasMultipleSigners()) {
                    signatures = signingInfo.getApkContentsSigners();
                } else {
                    signatures = signingInfo.getSigningCertificateHistory();
                }

            } else {

                packageInfo = pm.getPackageInfo(
                        ctx.getPackageName(),
                        PackageManager.GET_SIGNATURES
                );

                signatures = packageInfo.signatures;
            }

            if (signatures == null || signatures.length == 0) {

                return new TamperResult(
                        "APK Signature",
                        "No signatures found",
                        true
                );
            }

            MessageDigest md =
                    MessageDigest.getInstance("SHA-256");

            byte[] digest =
                    md.digest(signatures[0].toByteArray());

            StringBuilder sb = new StringBuilder();

            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }

            String currentSignature = sb.toString();

            if (!EXPECTED_SIGNATURE.equals(currentSignature)) {

                return new TamperResult(
                        "APK Signature",
                        "Signature mismatch",
                        true
                );
            }

            return new TamperResult(
                    "APK Signature",
                    "Signature verified",
                    false
            );

        } catch (Exception e) {

            return new TamperResult(
                    "APK Signature",
                    e.toString(),
                    true
            );
        }
    }

    // Check 1 - Xposed in the process
    private TamperResult checkXposedInProcess() {

        try {

            throw new Exception("hook_probe");

        } catch (Exception e) {

            for (StackTraceElement element : e.getStackTrace()) {

                String cls = element.getClassName();

                if (cls.contains("XposedBridge") ||
                        cls.contains("XC_MethodHook") ||
                        cls.contains("de.robv.android.xposed")) {

                    return new TamperResult(
                            "Xposed Hook Detected",
                            "Xposed is hooking this app: " + cls,
                            true
                    );
                }
            }
        }

        try {
            Class.forName("de.robv.android.xposed.XposedBridge");

            return new TamperResult(
                    "Xposed Hook Detected",
                    "XposedBridge class found",
                    true
            );

        } catch (ClassNotFoundException ignored) {
        }

        try {
            Class.forName("de.robv.android.xposed.XposedHelpers");

            return new TamperResult(
                    "Xposed Hook Detected",
                    "XposedHelpers class found",
                    true
            );

        } catch (ClassNotFoundException ignored) {
        }

        return new TamperResult(
                "Xposed Hook",
                "Not detected",
                false
        );
    }

    // Check 2 - Frida detection
    private TamperResult checkFridaInProcess() {

        try (BufferedReader br =
                     new BufferedReader(
                             new FileReader("/proc/self/maps"))) {

            String line;

            while ((line = br.readLine()) != null) {

                if (line.contains("frida") ||
                        line.contains("gum-js-loop") ||
                        line.contains("gmain") ||
                        line.contains("linjector") ||
                        line.contains("frida-agent")) {

                    return new TamperResult(
                            "Frida Detected",
                            "Found in process maps",
                            true
                    );
                }
            }

        } catch (Exception ignored) {
        }

        return new TamperResult(
                "Frida Hook",
                "Not detected",
                false
        );
    }

    // Check 3 - Suspicious libraries
    private TamperResult checkSuspiciousLibraries() {

        String[] suspicious = {
                "frida-agent",
                "frida-gadget",
                "gum-js-loop",
                "xposed",
                "lsposed",
                "lspatch",
                "lspd",
                "lsplant",
                "substrate",
                "cydia",
                "riru",
                "zygisk",
                "zygisk_loader",
                "libzygisk",
                "yahfa",
                "sandhook",
                "epic_hook",
                "whale.so",
                "magisk",
                "shamiko",
                "kernelsu",
                "apatch",
                "gameguardian",
                "libgg",
                "gg_temp",
                "cheatengine",
                "ce_server",
                "speedhack",
                "luckypatcher"
        };

        try (BufferedReader br =
                     new BufferedReader(
                             new FileReader("/proc/self/maps"))) {

            String line;

            while ((line = br.readLine()) != null) {

                String lower = line.toLowerCase();

                for (String lib : suspicious) {

                    if (lower.contains(lib)) {

                        return new TamperResult(
                                "Suspicious Library",
                                "Found: " + lib,
                                true
                        );
                    }
                }
            }

        } catch (Exception ignored) {
        }

        return new TamperResult(
                "Suspicious Libraries",
                "None detected",
                false
        );
    }

    // Check 4 - Stack trace
    private TamperResult checkStackTrace() {

        String[] indicators = {
                "XposedBridge",
                "XC_MethodHook",
                "LSPosed",
                "EdXposed",
                "yahfa",
                "lsplant",
                "substrate",
                "cydia"
        };

        StackTraceElement[] stack =
                Thread.currentThread().getStackTrace();

        for (StackTraceElement element : stack) {

            String cls = element.getClassName();

            for (String indicator : indicators) {

                if (cls.contains(indicator)) {

                    return new TamperResult(
                            "Stack Trace Hook",
                            "Hook found: " + cls,
                            true
                    );
                }
            }
        }

        return new TamperResult(
                "Stack Trace",
                "No hooks detected",
                false
        );
    }

    // Check 5 - Package name
    private TamperResult checkPackageName(Context ctx) {

        final String expectedPackage = "com.laert.rootchecker";
        String actualPackage = ctx.getPackageName();

        if (!expectedPackage.equals(actualPackage)) {

            return new TamperResult(
                    "Package Name",
                    "Package name mismatch: " + actualPackage,
                    true
            );
        }

        return new TamperResult(
                "Package Name",
                actualPackage,
                false
        );
    }

    // Check 6 - Debugger
    private TamperResult checkDebugger() {

        boolean debugger =
                android.os.Debug.isDebuggerConnected() ||
                        android.os.Debug.waitingForDebugger();

        return new TamperResult(
                "Debugger",
                debugger ? "Debugger detected" : "No debugger",
                debugger
        );
    }

    // Check 7 - Process tracing
    private TamperResult checkEmulatorProcess() {

        try (BufferedReader br =
                     new BufferedReader(
                             new FileReader("/proc/self/status"))) {

            String line;

            while ((line = br.readLine()) != null) {

                if (line.startsWith("TracerPid:")) {

                    int tracerPid =
                            Integer.parseInt(
                                    line.split(":")[1].trim());

                    if (tracerPid != 0) {

                        return new TamperResult(
                                "Process Trace",
                                "Tracer PID: " + tracerPid,
                                true
                        );
                    }

                    break;
                }
            }

        } catch (Exception ignored) {
        }

        return new TamperResult(
                "Process Trace",
                "No tracing detected",
                false
        );
    }

    // Check 8 - Hooking frameworks
    private TamperResult checkHookingFrameworks() {

        String[] paths = {

                "/system/framework/XposedBridge.jar",

                "/system/lib/libsubstrate.so",
                "/system/lib64/libsubstrate.so",

                "/data/adb/modules/lsposed",
                "/data/adb/modules/riru-lsposed",
                "/data/adb/modules/zygisk_lsposed",

                "/data/adb/modules/magisk",
                "/data/adb/modules/shamiko",
                "/data/adb/modules/zygisk",
                "/data/adb/modules/playintegrityfix",

                "/data/data/de.robv.android.xposed.installer",
                "/data/data/org.lsposed.manager",
                "/data/data/com.topjohnwu.magisk",
                "/data/adb/lspd",
                "/data/adb/modules/lspatch",
                "/data/adb/modules/lspatch-core",
                "/data/adb/modules/zygisk_next",
                "/data/adb/modules/zygisknext",
                "/data/adb/lspd",
                "/data/adb/lspd/log",
                "/data/adb/modules/lspd",
                "/data/adb/modules/lspatch",
                "/data/adb/modules/lspatch-core",
                "/data/adb/modules/zygisk",
                "/data/adb/modules/zygisk_next",
                "/data/adb/modules/zygisknext",
                "/data/adb/modules/shamiko",
                "/data/adb/modules/playintegrityfix",
                "/data/adb/modules/kernelsu",
                "/data/adb/ksu",
                "/data/adb/ap"

        };

        for (String path : paths) {

            if (new File(path).exists()) {

                return new TamperResult(
                        "Hooking Framework",
                        "Found: " + path,
                        true
                );
            }
        }

        return new TamperResult(
                "Hooking Frameworks",
                "None detected",
                false
        );
    }

    private TamperResult checkLSPatch() {

        String[] classNames = {
                "org.lsposed.lspatch.LSPAppComponentFactory",
                "org.lsposed.lspatch.LSPApplication",
                "org.lsposed.lspatch.LSPatch"
        };

        for (String cls : classNames) {
            try {
                Class.forName(cls);

                return new TamperResult(
                        "LSPatch",
                        "Detected class: " + cls,
                        true
                );

            } catch (ClassNotFoundException ignored) {
            }
        }

        try {

            ClassLoader loader = getClass().getClassLoader();

            if (loader != null) {

                String loaderName = loader.getClass().getName().toLowerCase();

                if (loaderName.contains("lspatch") ||
                        loaderName.contains("lsposed")) {

                    return new TamperResult(
                            "LSPatch",
                            "Suspicious ClassLoader: " + loaderName,
                            true
                    );
                }
            }

        } catch (Exception ignored) {
        }

        return new TamperResult(
                "LSPatch",
                "Not detected",
                false
        );
    }

    // Check 9 - Frida default ports
    private TamperResult checkFridaPorts() {

        final int[] ports = {27042, 27043};

        for (int port : ports) {

            try (java.net.Socket socket = new java.net.Socket()) {

                socket.connect(
                        new java.net.InetSocketAddress(
                                "127.0.0.1",
                                port),
                        100
                );

                return new TamperResult(
                        "Frida Port",
                        "Frida server detected on port " + port,
                        true
                );

            } catch (Exception ignored) {
            }
        }

        return new TamperResult(
                "Frida Port",
                "No Frida ports detected",
                false
        );
    }

    public static String getAppSignature(Context ctx) {

        try {

            PackageManager pm = ctx.getPackageManager();

            PackageInfo packageInfo;

            Signature[] signatures;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {

                packageInfo = pm.getPackageInfo(
                        ctx.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES
                );

                SigningInfo signingInfo =
                        packageInfo.signingInfo;

                if (signingInfo == null) {
                    return "ERROR";
                }

                if (signingInfo.hasMultipleSigners()) {
                    signatures =
                            signingInfo.getApkContentsSigners();
                } else {
                    signatures =
                            signingInfo.getSigningCertificateHistory();
                }

            } else {

                packageInfo = pm.getPackageInfo(
                        ctx.getPackageName(),
                        PackageManager.GET_SIGNATURES
                );

                signatures = packageInfo.signatures;
            }

            if (signatures == null || signatures.length == 0) {
                return "ERROR";
            }

            MessageDigest md =
                    MessageDigest.getInstance("SHA-256");

            byte[] digest =
                    md.digest(signatures[0].toByteArray());

            StringBuilder sb =
                    new StringBuilder();

            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }

            return sb.toString();

        } catch (Exception e) {

            return "ERROR: " + e.getMessage();

        }

    }

    private TamperResult checkVirtualEnvironment(Context ctx) {

        try {
            String dataDir = ctx.getApplicationInfo().dataDir;
            String lower = dataDir == null ? "" : dataDir.toLowerCase();
            String[] indicators = {"/virtual/", "/vs/", "multiapp", "parallel", "dual_", "shadow", "/va/"};
            for (int i = 0; i < indicators.length; i++) {
                if (lower.contains(indicators[i])) {
                    return new TamperResult(
                            "Virtual/Cloned Environment",
                            "Data directory looks virtualized: " + dataDir,
                            true
                    );
                }
            }
            return new TamperResult(
                    "Virtual/Cloned Environment",
                    "Normal data directory",
                    false
            );
        } catch (Exception e) {
            return new TamperResult(
                    "Virtual/Cloned Environment",
                    "Could not determine",
                    false
            );
        }
    }

    private TamperResult checkManifestIntegrity(Context ctx) {

        try {

            android.content.pm.ApplicationInfo appInfo =
                    ctx.getApplicationInfo();

            PackageInfo packageInfo =
                    ctx.getPackageManager().getPackageInfo(
                            ctx.getPackageName(),
                            0
                    );

            // Kontrollo package name
            if (!"com.laert.rootchecker".equals(packageInfo.packageName)) {

                return new TamperResult(
                        "Manifest Integrity",
                        "Package name modified",
                        true
                );
            }

            // Kontrollo që aplikacioni nuk është debuggable
            if ((appInfo.flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {

                return new TamperResult(
                        "Manifest Integrity",
                        "Application is debuggable",
                        true
                );
            }

            // Kontrollo allowBackup
            if ((appInfo.flags & android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) {

                return new TamperResult(
                        "Manifest Integrity",
                        "allowBackup is enabled",
                        true
                );
            }

            return new TamperResult(
                    "Manifest Integrity",
                    "Verified",
                    false
            );

        } catch (Exception e) {

            return new TamperResult(
                    "Manifest Integrity",
                    e.toString(),
                    true
            );
        }
    }
    private TamperResult checkClassLoader() {

        try {

            ClassLoader loader = getClass().getClassLoader();

            while (loader != null) {

                String name = loader.getClass().getName().toLowerCase();

                if (name.contains("lsposed") ||
                        name.contains("lspatch") ||
                        name.contains("xposed") ||
                        name.contains("zygisk")) {

                    return new TamperResult(
                            "ClassLoader",
                            "Suspicious: " + name,
                            true
                    );
                }

                loader = loader.getParent();
            }

        } catch (Exception ignored) {
        }

        return new TamperResult(
                "ClassLoader",
                "Normal",
                false
        );
    }
    private TamperResult checkAppComponentFactory(Context ctx) {

        try {

            ApplicationInfo ai = ctx.getApplicationInfo();

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {

                String factory = ai.appComponentFactory;

                if (factory != null &&
                        factory.toLowerCase().contains("lspatch")) {

                    return new TamperResult(
                            "AppComponentFactory",
                            factory,
                            true
                    );
                }
            }

        } catch (Exception ignored) {
        }

        return new TamperResult(
                "AppComponentFactory",
                "Normal",
                false
        );
    }
}