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
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class AntiTamper {

    private static final String EXPECTED_SIGNATURE =
            "177D0B6AC00A4D5DD3FE8269EC86951FCFFA134EAD8CBB13B6AE227AD03B4078";

    public static class TamperResult {

        public final String name;
        public final String detail;
        public final boolean detected;
        public final Severity severity;

        public TamperResult(String name,
                            String detail,
                            boolean detected) {
            this(name, detail, detected, detected ? Severity.MEDIUM : Severity.INFO);
        }

        public TamperResult(String name,
                            String detail,
                            boolean detected,
                            Severity severity) {

            this.name = name;
            this.detail = detail;
            this.detected = detected;
            this.severity = severity;
        }
    }

    public TamperResult[] runAllChecks(Context ctx) {

        List<TamperResult> results = new ArrayList<>();

        results.add(checkXposedInProcess());
        results.add(checkFridaInProcess());
        results.add(checkSuspiciousLibraries());
        results.add(checkStackTrace());
        results.add(checkAppSignature(ctx));
        results.add(checkRawApkSignature(ctx));
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
        results.add(checkMountNamespace());
        results.add(checkPowerUserApps(ctx));

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
                            true,
                            Severity.HIGH
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
                        true,
                        Severity.HIGH
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
                        "MISMATCH - expected " + EXPECTED_SIGNATURE.substring(0, 12)
                                + "... got " + currentSignature.substring(0, 12) + "...",
                        true,
                        Severity.HIGH
                );
            }

            return new TamperResult(
                    "APK Signature",
                    "Signature verified (matches " + currentSignature.substring(0, 12) + "...)",
                    false
            );

        } catch (Exception e) {

            return new TamperResult(
                    "APK Signature",
                    e.toString(),
                    true,
                    Severity.HIGH
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
    private TamperResult checkRawApkSignature(Context ctx) {
        ZipFile zip = null;
        try {
            String apkPath = ctx.getPackageCodePath();
            zip = new ZipFile(apkPath);

            ZipEntry sigEntry = null;
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (name.startsWith("META-INF/") &&
                        (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    sigEntry = e;
                    break;
                }
            }

            if (sigEntry == null) {
                return new TamperResult(
                        "Raw APK Signature",
                        "No V1 (JAR) signature block found in APK file",
                        true,
                        Severity.HIGH
                );
            }

            InputStream is = zip.getInputStream(sigEntry);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(is);
            is.close();

            if (certs.isEmpty()) {
                return new TamperResult(
                        "Raw APK Signature",
                        "Could not parse certificate from " + sigEntry.getName(),
                        true,
                        Severity.HIGH
                );
            }

            Certificate cert = certs.iterator().next();

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());

            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }
            String currentSignature = sb.toString();

            if (!EXPECTED_SIGNATURE.equals(currentSignature)) {
                return new TamperResult(
                        "Raw APK Signature",
                        "MISMATCH (read from disk, bypasses PackageManager) - got "
                                + currentSignature.substring(0, 12) + "...",
                        true,
                        Severity.HIGH
                );
            }

            return new TamperResult(
                    "Raw APK Signature",
                    "Verified directly from APK file bytes (matches "
                            + currentSignature.substring(0, 12) + "...)",
                    false
            );

        } catch (Exception e) {
            return new TamperResult(
                    "Raw APK Signature",
                    "Error: " + e.toString(),
                    true,
                    Severity.HIGH
            );
        } finally {
            if (zip != null) {
                try { zip.close(); } catch (Exception ignored) {}
            }
        }
    }

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
                            true,
                            Severity.LOW
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

    private TamperResult checkMountNamespace() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            List<String> suspicious = new ArrayList<>();
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                boolean overlayOnSystem = lower.contains(" overlay ") &&
                        (lower.contains(" /system") || lower.contains(" /vendor")
                                || lower.contains(" /product") || lower.contains(" /apex"));
                boolean debugRamdisk = lower.contains("/debug_ramdisk");
                boolean tmpfsOnSystem = lower.contains(" tmpfs ") && lower.contains(" /system");
                if (overlayOnSystem || debugRamdisk || tmpfsOnSystem) {
                    suspicious.add(line.trim());
                    if (suspicious.size() >= 3) break;
                }
            }
            if (!suspicious.isEmpty()) {
                String sample = suspicious.get(0);
                if (sample.length() > 90) sample = sample.substring(0, 90) + "...";
                return new TamperResult(
                        "Mount Namespace",
                        suspicious.size() + " suspicious mount(s), e.g.: " + sample,
                        true,
                        Severity.HIGH
                );
            }
            return new TamperResult(
                    "Mount Namespace",
                    "No overlay/tmpfs mounts found on /system, /vendor, /product, /apex",
                    false
            );
        } catch (Exception e) {
            return new TamperResult(
                    "Mount Namespace",
                    "Could not read mount namespace",
                    false,
                    Severity.INFO
            );
        } finally {
            if (br != null) { try { br.close(); } catch (Exception ignored) {} }
        }
    }

    private TamperResult checkPowerUserApps(Context ctx) {
        String[][] apps = {
                {"moe.shizuku.privileged.api", "Shizuku"},
                {"com.termux", "Termux"},
                {"bin.mt.plus", "MT Manager"}
        };
        List<String> found = new ArrayList<>();
        if (ctx != null) {
            PackageManager pm = ctx.getPackageManager();
            for (int i = 0; i < apps.length; i++) {
                try {
                    pm.getPackageInfo(apps[i][0], 0);
                    found.add(apps[i][1]);
                } catch (Exception ignored) {
                }
            }
        }
        if (found.isEmpty()) {
            return new TamperResult(
                    "Power-User Apps",
                    "None of the common developer/power-user tools detected",
                    false,
                    Severity.INFO
            );
        }
        return new TamperResult(
                "Power-User Apps",
                "Detected: " + found + " - legitimate developer tools, not treated as root evidence",
                false,
                Severity.INFO
        );
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

            if (!"com.laert.rootchecker".equals(packageInfo.packageName)) {

                return new TamperResult(
                        "Manifest Integrity",
                        "Package name modified",
                        true,
                        Severity.HIGH
                );
            }

            if ((appInfo.flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {

                return new TamperResult(
                        "Manifest Integrity",
                        "Application is debuggable",
                        true,
                        Severity.MEDIUM
                );
            }

            if ((appInfo.flags & android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) {

                return new TamperResult(
                        "Manifest Integrity",
                        "allowBackup is enabled",
                        true,
                        Severity.LOW
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
                    true,
                    Severity.MEDIUM
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
                            true,
                            Severity.HIGH
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
                            true,
                            Severity.HIGH
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

    private TamperResult checkMountNamespace() {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            List<String> suspicious = new ArrayList<>();
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                boolean overlayOnSystem = lower.contains(" overlay ") &&
                        (lower.contains(" /system") || lower.contains(" /vendor")
                                || lower.contains(" /product") || lower.contains(" /apex"));
                boolean debugRamdisk = lower.contains("/debug_ramdisk");
                boolean tmpfsOnSystem = lower.contains(" tmpfs ") && lower.contains(" /system");
                if (overlayOnSystem || debugRamdisk || tmpfsOnSystem) {
                    suspicious.add(line.trim());
                    if (suspicious.size() >= 3) break;
                }
            }
            if (!suspicious.isEmpty()) {
                String sample = suspicious.get(0);
                if (sample.length() > 90) sample = sample.substring(0, 90) + "...";
                return new TamperResult(
                        "Mount Namespace",
                        suspicious.size() + " suspicious mount(s), e.g.: " + sample,
                        true,
                        Severity.HIGH
                );
            }
            return new TamperResult(
                    "Mount Namespace",
                    "No overlay/tmpfs mounts found on /system, /vendor, /product, /apex",
                    false
            );
        } catch (Exception e) {
            return new TamperResult(
                    "Mount Namespace",
                    "Could not read mount namespace",
                    false,
                    Severity.INFO
            );
        } finally {
            if (br != null) { try { br.close(); } catch (Exception ignored) {} }
        }
    }

    private TamperResult checkPowerUserApps(Context ctx) {
        String[][] apps = {
                {"moe.shizuku.privileged.api", "Shizuku"},
                {"com.termux", "Termux"},
                {"bin.mt.plus", "MT Manager"}
        };
        List<String> found = new ArrayList<>();
        if (ctx != null) {
            PackageManager pm = ctx.getPackageManager();
            for (int i = 0; i < apps.length; i++) {
                try {
                    pm.getPackageInfo(apps[i][0], 0);
                    found.add(apps[i][1]);
                } catch (Exception ignored) {
                }
            }
        }
        if (found.isEmpty()) {
            return new TamperResult(
                    "Power-User Apps",
                    "None of the common developer/power-user tools detected",
                    false,
                    Severity.INFO
            );
        }
        return new TamperResult(
                "Power-User Apps",
                "Detected: " + found + " - legitimate developer tools, not treated as root evidence",
                false,
                Severity.INFO
        );
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
                    
            if (!"com.laert.rootchecker".equals(packageInfo.packageName)) {

                return new TamperResult(
                        "Manifest Integrity",
                        "Package name modified",
                        true,
                        Severity.HIGH
                );
            }
                );
            }
            if ((appInfo.flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {

                return new TamperResult(
                        "Manifest Integrity",
                        "Application is debuggable",
                        true,
                        Severity.MEDIUM
                );
            }

            if ((appInfo.flags & android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) {

                return new TamperResult(
                        "Manifest Integrity",
                        "allowBackup is enabled",
                        true,
                        Severity.LOW
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
                    true,
                    Severity.MEDIUM
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
                            true,
                            Severity.HIGH
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
                            true,
                            Severity.HIGH
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
