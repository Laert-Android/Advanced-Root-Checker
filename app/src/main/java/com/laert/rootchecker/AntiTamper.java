package com.laert.rootchecker;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class AntiTamper {

    public static class TamperResult {
        public final String name;
        public final String detail;
        public final boolean detected;

        public TamperResult(String name, String detail, boolean detected) {
            this.name = name;
            this.detail = detail;
            this.detected = detected;
        }
    }

    private static final String EXPECTED_SIGNATURE = "177D0B6AC00A4D5DD3FE8269EC86951FCFFA134EAD8CBB13B6AE227AD03B4078";
    public TamperResult[] runAllChecks(Context ctx) {
        List results = new ArrayList();
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
        return (TamperResult[]) results.toArray(
                new TamperResult[results.size()]);
    }

    // Check 1 - Xposed in the process
    private TamperResult checkXposedInProcess() {
        try {
            throw new Exception("hook_probe");
        } catch (Exception e) {
            StackTraceElement[] stack = e.getStackTrace();
            for (int i = 0; i < stack.length; i++) {
                String cls = stack[i].getClassName();
                if (cls.contains("XposedBridge") ||
                        cls.contains("XC_MethodHook") ||
                        cls.contains("de.robv.android.xposed")) {
                    return new TamperResult("Xposed Hook Detected",
                            "Xposed is hooking this app: " + cls, true);
                }
            }
        }
        // Check for Xposed in loaded classes
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return new TamperResult("Xposed Hook Detected",
                    "XposedBridge class found in process", true);
        } catch (ClassNotFoundException e) {}
        try {
            Class.forName("de.robv.android.xposed.XposedHelpers");
            return new TamperResult("Xposed Hook Detected",
                    "XposedHelpers class found in process", true);
        } catch (ClassNotFoundException e) {}
        return new TamperResult("Xposed Hook",
                "Not detected in this process", false);
    }

    // Check 2 - Frida detection
    private TamperResult checkFridaInProcess() {
        // Check for Frida agent in maps
        try {
            BufferedReader br = new BufferedReader(
                    new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("frida") ||
                        line.contains("gum-js-loop") ||
                        line.contains("gmain") ||
                        line.contains("linjector") ||
                        line.contains("frida-agent")) {
                    br.close();
                    return new TamperResult("Frida Detected",
                            "Frida found in process maps: " +
                                    line.substring(0, Math.min(50, line.length())),
                            true);
                }
            }
            br.close();
        } catch (Exception e) {}
        return new TamperResult("Frida Hook",
                "Not detected in process maps", false);
    }

    // Check 3 - Suspicious libraries loaded
    private TamperResult checkSuspiciousLibraries() {
        String[] suspicious = {
                "frida-agent",
                "frida-gadget",
                "xposed",
                "substrate",
                "cydia",
                "lsplant",
                "riru",
                "zygisk_loader",
                "lspatch",
                "yahfa",
                "sandhook",
                "epic_hook",
                "whale.so"
        };
        try {
            BufferedReader br = new BufferedReader(
                    new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                String lineLower = line.toLowerCase();
                for (int i = 0; i < suspicious.length; i++) {
                    if (lineLower.contains(suspicious[i])) {
                        br.close();
                        return new TamperResult(
                                "Suspicious Library",
                                "Found: " + suspicious[i] +
                                        " in loaded libraries", true);
                    }
                }
            }
            br.close();
        } catch (Exception e) {}
        return new TamperResult("Suspicious Libraries",
                "None found in process", false);
    }

    // Check 4 - Stack trace analysis
    private TamperResult checkStackTrace() {
        String[] hookIndicators = {
                "XposedBridge", "XC_MethodHook",
                "LSPosed", "EdXposed",
                "yahfa", "lsplant",
                "substrate", "cydia"
        };
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (int i = 0; i < stack.length; i++) {
            String cls = stack[i].getClassName();
            for (int j = 0; j < hookIndicators.length; j++) {
                if (cls.contains(hookIndicators[j])) {
                    return new TamperResult("Stack Trace Hook",
                            "Hook found in stack: " + cls, true);
                }
            }
        }
        return new TamperResult("Stack Trace",
                "No hooks found in call stack", false);
    }

    // Check 5 - APK signature verification
    private TamperResult checkAppSignature(Context ctx) {
        try {
            PackageInfo info = ctx.getPackageManager().getPackageInfo(
                    ctx.getPackageName(),
                    PackageManager.GET_SIGNATURES);
            Signature[] signatures = info.signatures;
            if (signatures == null || signatures.length == 0) {
                return new TamperResult("APK Signature",
                        "No signatures found - app may be tampered!", true);
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(signatures[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                sb.append(String.format("%02X", digest[i]));
            }
            String currentSig = sb.toString();

            if (!EXPECTED_SIGNATURE.equals("YOUR_SIGNATURE_HERE") &&
                    !EXPECTED_SIGNATURE.equals(currentSig)) {
                return new TamperResult("APK Signature",
                        "Signature mismatch! App may be repackaged.", true);
            }
            return new TamperResult("APK Signature",
                    "Signature: " + currentSig.substring(0, 16) + "...",
                    false);
        } catch (Exception e) {
            return new TamperResult("APK Signature",
                    "Could not verify: " + e.getMessage(), true);
        }
    }

    // Check 6 - Package name check
    private TamperResult checkPackageName(Context ctx) {
        String expected = "com.laert.rootchecker";
        String actual = ctx.getPackageName();
        boolean tampered = !expected.equals(actual);
        return new TamperResult("Package Name",
                "Package: " + actual,
                tampered);
    }

    // Check 7 - Debugger attached
    private TamperResult checkDebugger() {
        boolean debugging = android.os.Debug.isDebuggerConnected();
        if (!debugging) {
            debugging = android.os.Debug.waitingForDebugger();
        }
        return new TamperResult("Debugger",
                debugging ? "Debugger is attached!" : "No debugger attached",
                debugging);
    }

    // Check 8 - Emulator process check
    private TamperResult checkEmulatorProcess() {
        try {
            BufferedReader br = new BufferedReader(
                    new FileReader("/proc/self/status"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String[] parts = line.split(":");
                    if (parts.length > 1) {
                        int tracerPid = Integer.parseInt(parts[1].trim());
                        br.close();
                        if (tracerPid != 0) {
                            return new TamperResult("Process Trace",
                                    "Process is being traced! PID: " + tracerPid,
                                    true);
                        }
                    }
                    break;
                }
            }
            br.close();
        } catch (Exception e) {}
        return new TamperResult("Process Trace",
                "No process tracing detected", false);
    }

    // Check 9 - Hooking frameworks
    private TamperResult checkHookingFrameworks() {
        String[] frameworks = {
                "/data/data/de.robv.android.xposed.installer",
                "/data/data/org.lsposed.manager",
                "/data/data/com.elderdrivers.riru.edxp",
                "/data/app/de.robv.android.xposed.installer",
                "/system/framework/XposedBridge.jar",
                "/system/lib/libsubstrate.so",
                "/system/lib64/libsubstrate.so",
                "/data/adb/modules/lsposed",
                "/data/adb/modules/riru-lsposed",
                "/data/adb/modules/zygisk_lsposed"
        };
        for (int i = 0; i < frameworks.length; i++) {
            if (new File(frameworks[i]).exists()) {
                return new TamperResult("Hooking Framework",
                        "Found: " + frameworks[i], true);
            }
        }
        return new TamperResult("Hooking Frameworks",
                "None detected", false);
    }

    // Check 10 - Frida ports
    private TamperResult checkFridaPorts() {
        // Frida default ports
        int[] ports = {27042, 27043};
        for (int i = 0; i < ports.length; i++) {
            try {
                java.net.Socket socket = new java.net.Socket();
                socket.connect(
                        new java.net.InetSocketAddress("127.0.0.1", ports[i]),
                        50);
                socket.close();
                return new TamperResult("Frida Port",
                        "Frida server detected on port " + ports[i], true);
            } catch (Exception e) {}
        }
        return new TamperResult("Frida Port",
                "No Frida server ports open", false);
    }

    public static String getAppSignature(Context ctx) {
        try {
            PackageInfo info = ctx.getPackageManager().getPackageInfo(
                    ctx.getPackageName(),
                    PackageManager.GET_SIGNATURES);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(info.signatures[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                sb.append(String.format("%02X", digest[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}