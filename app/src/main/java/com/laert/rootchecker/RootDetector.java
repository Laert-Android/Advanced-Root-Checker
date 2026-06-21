package com.laert.rootchecker;

import android.os.Build;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class RootDetector {

    public static class CheckResult {
        public final String name;
        public final String detail;
        public final String explanation;
        public final boolean detected;
        public final int weight;

        public CheckResult(String name, String detail, String explanation, boolean detected, int weight) {
            this.name = name;
            this.detail = detail;
            this.explanation = explanation;
            this.detected = detected;
            this.weight = weight;
        }
    }

    public CheckResult[] runAllChecks() {
        List results = new ArrayList();
        results.add(checkSuBinary());
        results.add(checkSuInPath());
        results.add(checkBusybox());
        results.add(checkSuperuserApk());
        results.add(checkMagisk());
        results.add(checkZygisk());
        results.add(checkMagiskModules());
        results.add(checkKnownRootApps());
        results.add(checkPotentiallyDangerousApps());
        results.add(checkRootCloakingApps());
        results.add(checkBuildTags());
        results.add(checkTestKeys());
        results.add(checkDangerousProps());
        results.add(checkRWSystem());
        results.add(checkSelinuxEnforcing());
        results.add(checkRootNativeTest());
        results.add(checkWritableSystem());
        results.add(checkHiddenSuBinaries());
        results.add(checkXposed());
        results.add(checkPlayIntegrity());
        results.add(checkEmulator());
        results.add(checkAdbEnabled());
        results.add(checkDeveloperOptions());
        results.add(checkOTADisabled());
        results.add(checkMagiskDenyList());
        results.add(checkZygiskModules());
        results.add(checkKernelSU());
        results.add(checkAPatch());
        results.add(checkVerifiedBoot());
        results.add(checkKnox());
        results.add(checkAntiRollback());
        results.add(checkTreble());
        results.add(checkNativeRoot());
        return (CheckResult[]) results.toArray(new CheckResult[results.size()]);
    }

    public int calculateRiskScore(CheckResult[] checks) {
        int totalWeight = 0;
        int detectedWeight = 0;
        for (int i = 0; i < checks.length; i++) {
            totalWeight += checks[i].weight;
            if (checks[i].detected) {
                detectedWeight += checks[i].weight;
            }
        }
        if (totalWeight == 0) return 100;
        int score = 100 - (int)((float)detectedWeight / totalWeight * 100);
        return score;
    }

    private CheckResult checkSuBinary() {
        String[] paths = {"/system/bin/su","/system/xbin/su","/sbin/su",
            "/data/local/xbin/su","/data/local/bin/su",
            "/data/local/su","/su/bin/su","/magisk/.core/bin/su"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("SuperUser Binary",
                    "Found at: "+paths[i],
                    "The 'su' binary grants superuser access. Its presence strongly indicates root.",
                    true, 10);
        }
        return new CheckResult("SuperUser Binary","Not found in common paths",
            "The 'su' binary grants superuser access. Its presence strongly indicates root.",
            false, 10);
    }

    private CheckResult checkSuInPath() {
        String path = System.getenv("PATH");
        if (path != null) {
            String[] dirs = path.split(":");
            for (int i = 0; i < dirs.length; i++) {
                if (new File(dirs[i],"su").exists())
                    return new CheckResult("su in PATH","Found in: "+dirs[i],
                        "If 'su' is in PATH, any app can easily request root access.",
                        true, 8);
            }
        }
        return new CheckResult("su in PATH","Not found in PATH",
            "If 'su' is in PATH, any app can easily request root access.",
            false, 8);
    }

    private CheckResult checkBusybox() {
        String[] paths = {"/system/bin/busybox","/system/xbin/busybox",
            "/sbin/busybox","/su/xbin/busybox"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("BusyBox Binary","Found at: "+paths[i],
                    "BusyBox provides Unix tools often installed alongside root. Indicates root access.",
                    true, 6);
        }
        return new CheckResult("BusyBox Binary","Not present",
            "BusyBox provides Unix tools often installed alongside root. Indicates root access.",
            false, 6);
    }

    private CheckResult checkSuperuserApk() {
        String[] paths = {"/system/app/Superuser.apk","/system/app/SuperSU/SuperSU.apk",
            "/system/app/SuperSU.apk","/system/priv-app/Superuser.apk"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("SuperUser Exists","Found: "+paths[i],
                    "SuperUser/SuperSU APK in system partition confirms the device is rooted.",
                    true, 10);
        }
        return new CheckResult("SuperUser Exists","Not in system",
            "SuperUser/SuperSU APK in system partition confirms the device is rooted.",
            false, 10);
    }

    private CheckResult checkMagisk() {
        String[] paths = {"/sbin/.magisk","/sbin/.core/mirror",
            "/sbin/.core/img","/data/adb/magisk",
            "/data/adb/magisk.db","/magisk",
            "/data/adb/magisk/busybox"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Magisk","Detected: "+paths[i],
                    "Magisk is the most popular root solution. It provides systemless root and module support.",
                    true, 10);
        }
        return new CheckResult("Magisk","No Magisk artifacts found",
            "Magisk is the most popular root solution. It provides systemless root and module support.",
            false, 10);
    }

    private CheckResult checkZygisk() {
        String[] paths = {"/data/adb/modules/.zygisk",
            "/dev/.magisk/zygisk",
            "/system/lib/libzygisk.so",
            "/system/lib64/libzygisk.so"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Zygisk","Detected: "+paths[i],
                    "Zygisk runs code in every app process. Used for advanced root hiding and modules.",
                    true, 8);
        }
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/getprop","persist.sys.zygisk"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if ("true".equals(val != null ? val.trim() : ""))
                return new CheckResult("Zygisk","persist.sys.zygisk=true",
                    "Zygisk runs code in every app process. Used for advanced root hiding and modules.",
                    true, 8);
        } catch (Exception e) {}
        return new CheckResult("Zygisk","Not detected",
            "Zygisk runs code in every app process. Used for advanced root hiding and modules.",
            false, 8);
    }

    private CheckResult checkMagiskModules() {
        File modulesDir = new File("/data/adb/modules");
        if (modulesDir.exists() && modulesDir.isDirectory()) {
            String[] modules = modulesDir.list();
            if (modules != null && modules.length > 0)
                return new CheckResult("Magisk Modules",
                    modules.length+" module(s) installed",
                    "Magisk modules modify system behavior. Their presence confirms Magisk is installed.",
                    true, 5);
        }
        return new CheckResult("Magisk Modules","No modules found",
            "Magisk modules modify system behavior. Their presence confirms Magisk is installed.",
            false, 5);
    }

    private CheckResult checkKnownRootApps() {
        String[] packages = {
            "com.noshufou.android.su","eu.chainfire.supersu",
            "com.koushikdutta.superuser","com.thirdparty.superuser",
            "com.topjohnwu.magisk","com.kingroot.kinguser",
            "com.kingo.root","com.smedialink.oneclickroot",
            "com.alephzain.framaroot"};
        for (int i = 0; i < packages.length; i++) {
            if (new File("/data/data/"+packages[i]).exists())
                return new CheckResult("Root Management Apps","Detected: "+packages[i],
                    "Root management apps control which apps get root access on your device.",
                    true, 9);
        }
        return new CheckResult("Root Management Apps","None detected",
            "Root management apps control which apps get root access on your device.",
            false, 9);
    }

    private CheckResult checkPotentiallyDangerousApps() {
        String[] packages = {
            "com.chelpus.lackypatch","com.dimonvideo.luckypatcher",
            "com.forpda.lp","com.chelpus.luckypatcher",
            "com.gameguardian.android","catch_.me_.if_.you_.can_",
            "com.android.vending.billing.InAppBillingService.LUCK",
            "com.android.vending.billing.InAppBillingService.LOCK"};
        for (int i = 0; i < packages.length; i++) {
            if (new File("/data/data/"+packages[i]).exists())
                return new CheckResult("Potentially Dangerous Apps","Detected: "+packages[i],
                    "Apps like Lucky Patcher can bypass in-app purchases and modify other apps.",
                    true, 7);
        }
        return new CheckResult("Potentially Dangerous Apps","None detected",
            "Apps like Lucky Patcher can bypass in-app purchases and modify other apps.",
            false, 7);
    }

    private CheckResult checkRootCloakingApps() {
        String[] packages = {
            "com.devadvance.rootcloak","com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer","com.saurik.substrate",
            "com.amphoras.hidemyroot","com.formyhm.hideroot","me.phh.superuser"};
        for (int i = 0; i < packages.length; i++) {
            if (new File("/data/data/"+packages[i]).exists())
                return new CheckResult("Root Cloaking Apps","Detected: "+packages[i],
                    "Root cloaking apps hide root from other apps like banking apps and game anti-cheat.",
                    true, 8);
        }
        String[] paths = {"/data/adb/modules/shamiko",
            "/data/adb/modules/MagiskHide","/data/adb/modules/zygisk_shamiko"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Root Cloaking Apps","Shamiko/MagiskHide detected",
                    "Root cloaking apps hide root from other apps like banking apps and game anti-cheat.",
                    true, 8);
        }
        return new CheckResult("Root Cloaking Apps","None detected",
            "Root cloaking apps hide root from other apps like banking apps and game anti-cheat.",
            false, 8);
    }

    private CheckResult checkBuildTags() {
        String tags = Build.TAGS;
        if (tags != null && tags.contains("test-keys"))
            return new CheckResult("Test Keys","Signed with test-keys: "+tags,
                "Official Android builds use release-keys. Test-keys indicate a custom or rooted build.",
                true, 7);
        return new CheckResult("Test Keys","Tags: "+(tags!=null?tags:"null"),
            "Official Android builds use release-keys. Test-keys indicate a custom or rooted build.",
            false, 7);
    }

    private CheckResult checkTestKeys() {
        String fp = Build.FINGERPRINT;
        boolean suspect = false;
        if (fp != null) {
            String fpl = fp.toLowerCase();
            if (fpl.contains("generic")||fpl.contains("test-keys")||fpl.contains("debug")) suspect = true;
        }
        String display = fp!=null?fp.substring(0,Math.min(60,fp.length())):"null";
        return new CheckResult("Fingerprint Check",display,
            "The build fingerprint identifies the exact software on your device. Anomalies suggest modification.",
            suspect, 6);
    }

    private CheckResult checkDangerousProps() {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/getprop"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line; String found = null;
            while ((line=br.readLine())!=null) {
                if ((line.contains("ro.debuggable")&&line.contains("[1]"))
                    ||(line.contains("ro.secure")&&line.contains("[0]"))
                    ||(line.contains("service.adb.root")&&line.contains("[1]"))) {
                    found=line.trim(); break;
                }
            }
            br.close(); p.destroy();
            if (found!=null)
                return new CheckResult("Dangerous Props",found,
                    "System properties like ro.debuggable=1 indicate a debug build that is easier to exploit.",
                    true, 8);
        } catch (Exception e) {}
        return new CheckResult("Dangerous Props","No dangerous system properties",
            "System properties like ro.debuggable=1 indicate a debug build that is easier to exploit.",
            false, 8);
    }

    private CheckResult checkRWSystem() {
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/mounts"));
            String line;
            while ((line=br.readLine())!=null) {
                String[] parts = line.split(" ");
                if (parts.length>=4&&parts[1].equals("/system")) {
                    String opts = parts[3]; br.close();
                    boolean rw = opts.startsWith("rw");
                    return new CheckResult("Read/Write Paths","Mounted as: "+opts.split(",")[0],
                        "The /system partition should be read-only. If writable, system files can be modified.",
                        rw, 9);
                }
            }
            br.close();
        } catch (Exception e) {}
        return new CheckResult("Read/Write Paths","Could not determine (likely read-only)",
            "The /system partition should be read-only. If writable, system files can be modified.",
            false, 9);
    }

    private CheckResult checkSelinuxEnforcing() {
        try {
            File f = new File("/sys/fs/selinux/enforce");
            if (f.exists()) {
                BufferedReader br = new BufferedReader(new FileReader(f));
                String val = br.readLine(); br.close();
                boolean permissive = "0".equals(val!=null?val.trim():"1");
                return new CheckResult("SELinux Status",
                    permissive?"PERMISSIVE":"Enforcing",
                    "SELinux enforces security policies. Permissive mode disables these protections.",
                    permissive, 8);
            }
        } catch (Exception e) {}
        return new CheckResult("SELinux Status","Could not read enforce file",
            "SELinux enforces security policies. Permissive mode disables these protections.",
            false, 8);
    }

    private CheckResult checkRootNativeTest() {
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"su","-c","id"});
            BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String output = br.readLine(); br.close(); proc.destroy();
            if (output!=null&&output.contains("uid=0"))
                return new CheckResult("Root Native Test",
                    output.substring(0,Math.min(50,output.length())),
                    "This test actually executes su to check if root commands work on this device.",
                    true, 10);
        } catch (Exception e) {}
        return new CheckResult("Root Native Test","su command failed or denied",
            "This test actually executes su to check if root commands work on this device.",
            false, 10);
    }

    private CheckResult checkWritableSystem() {
        File testFile = new File("/system/.rootcheck_test");
        try {
            boolean created = testFile.createNewFile();
            if (created) { testFile.delete();
                return new CheckResult("Writable /system","/system is writable",
                    "Being able to write to /system means system files can be permanently modified.",
                    true, 10); }
        } catch (Exception e) {}
        return new CheckResult("Writable /system","/system is not writable",
            "Being able to write to /system means system files can be permanently modified.",
            false, 10);
    }

    private CheckResult checkHiddenSuBinaries() {
        String[] paths = {"/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup","/system/xbin/mu"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Hidden su Binaries","Found: "+paths[i],
                    "Some root methods hide su in unusual locations to avoid detection.",
                    true, 7);
        }
        return new CheckResult("Hidden su Binaries","None found",
            "Some root methods hide su in unusual locations to avoid detection.",
            false, 7);
    }

    private CheckResult checkXposed() {
        String[] paths = {"/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/data/data/de.robv.android.xposed.installer"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Xposed Framework","Detected: "+paths[i],
                    "Xposed can hook and modify any app. It requires root and significantly reduces security.",
                    true, 9);
        }
        try {
            throw new Exception("probe");
        } catch (Exception e) {
            StackTraceElement[] stack = e.getStackTrace();
            for (int i = 0; i < stack.length; i++) {
                if (stack[i].getClassName().contains("XposedBridge"))
                    return new CheckResult("Xposed Framework","Found in stack trace",
                        "Xposed can hook and modify any app. It requires root and significantly reduces security.",
                        true, 9);
            }
        }
        return new CheckResult("Xposed Framework","Not detected",
            "Xposed can hook and modify any app. It requires root and significantly reduces security.",
            false, 9);
    }

    private CheckResult checkPlayIntegrity() {
        String tags = Build.TAGS;
        String fp = Build.FINGERPRINT;
        String type = Build.TYPE;
        boolean fail = false; String reason = "";
        if (tags != null && tags.contains("test-keys")) {
            fail = true; reason = "test-keys build";
        } else if ("eng".equals(type) || "userdebug".equals(type)) {
            fail = true; reason = "Build type: " + type;
        } else if (fp != null && (fp.contains("generic") || fp.contains("unknown"))) {
            fail = true; reason = "Generic fingerprint";
        } else if (new File("/data/adb/magisk").exists()) {
            fail = true; reason = "Magisk detected";
        }
        return new CheckResult("Play Integrity Heuristics (Offline)",
                fail ? "Local signals suggest FAIL: " + reason : "No local red flags found",
                "This is NOT a real Play Integrity API verdict. The real Play Integrity API requires " +
                        "an internet connection to verify with Google's servers, which this app intentionally " +
                        "does not use. This check only approximates the result using local build signals " +
                        "(test-keys, build type, fingerprint, Magisk presence) and can be wrong in either direction.",
                fail, 7);
    }

    private CheckResult checkEmulator() {
        boolean isEmulator = false; String reason = "Real device detected";
        if (Build.FINGERPRINT != null && Build.FINGERPRINT.contains("generic")) {
            isEmulator = true; reason = "Generic fingerprint";
        } else if ("goldfish".equals(Build.HARDWARE) || "ranchu".equals(Build.HARDWARE)) {
            isEmulator = true; reason = "Hardware: " + Build.HARDWARE;
        } else if (Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK")) {
            isEmulator = true; reason = "Model: " + Build.MODEL;
        } else if (new File("/dev/socket/qemud").exists()) {
            isEmulator = true; reason = "QEMU socket found";
        }
        return new CheckResult("Emulator Detection",reason,
            "Running on an emulator may indicate automated testing or analysis of your device.",
            isEmulator, 5);
    }

    private CheckResult checkAdbEnabled() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","persist.service.adb.enable"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if ("1".equals(val != null ? val.trim() : ""))
                return new CheckResult("ADB Status","ADB is enabled",
                    "ADB allows full device access from a computer. Should be disabled for security.",
                    true, 4);
        } catch (Exception e) {}
        return new CheckResult("ADB Status","ADB not enabled via prop",
            "ADB allows full device access from a computer. Should be disabled for security.",
            false, 4);
    }

    private CheckResult checkDeveloperOptions() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","persist.sys.usb.config"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if (val != null && val.contains("adb"))
                return new CheckResult("Developer Options","USB config: "+val.trim(),
                    "Developer options enable debugging features that can be used to access device data.",
                    true, 4);
        } catch (Exception e) {}
        return new CheckResult("Developer Options","ADB not in USB config",
            "Developer options enable debugging features that can be used to access device data.",
            false, 4);
    }

    private CheckResult checkOTADisabled() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","ro.ota.disable"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if ("1".equals(val!=null?val.trim():"") || "true".equals(val!=null?val.trim():""))
                return new CheckResult("OTA Updates","OTA updates disabled",
                    "Disabled OTA updates means the device cannot receive security patches automatically.",
                    true, 5);
        } catch (Exception e) {}
        return new CheckResult("OTA Updates","OTA updates enabled",
            "OTA updates deliver important security patches. Keeping them enabled is recommended.",
            false, 5);
    }

    private CheckResult checkMagiskDenyList() {
        if (new File("/data/adb/magisk/deny").exists() ||
            new File("/data/adb/magisk/denylist.db").exists())
            return new CheckResult("Magisk DenyList","DenyList enabled",
                "DenyList hides root from specific apps. Indicates active root hiding attempts.",
                true, 6);
        return new CheckResult("Magisk DenyList","Not detected",
            "DenyList hides root from specific apps. Indicates active root hiding attempts.",
            false, 6);
    }

    private CheckResult checkZygiskModules() {
        File zygiskDir = new File("/data/adb/modules");
        if (zygiskDir.exists() && zygiskDir.isDirectory()) {
            File[] modules = zygiskDir.listFiles();
            if (modules != null) {
                for (int i = 0; i < modules.length; i++) {
                    if (new File(modules[i], "zygisk").exists())
                        return new CheckResult("Zygisk Modules",
                            "Zygisk module: "+modules[i].getName(),
                            "Zygisk modules inject code into apps and can bypass security checks.",
                            true, 7);
                }
            }
        }
        return new CheckResult("Zygisk Modules","No Zygisk modules found",
            "Zygisk modules inject code into apps and can bypass security checks.",
            false, 7);
    }

    private CheckResult checkKernelSU() {
        String[] paths = {"/data/adb/ksud","/data/adb/ksu","/system/bin/ksud"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("KernelSU","Detected: "+paths[i],
                    "KernelSU provides root at the kernel level, making it harder to detect than Magisk.",
                    true, 10);
        }
        return new CheckResult("KernelSU","Not detected",
            "KernelSU provides root at the kernel level, making it harder to detect than Magisk.",
            false, 10);
    }

    private CheckResult checkAPatch() {
        String[] paths = {"/data/adb/ap","/data/adb/apatch","/data/adb/apatch/apatchd"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("APatch","Detected: "+paths[i],
                    "APatch is a kernel-based root solution similar to KernelSU.",
                    true, 10);
        }
        return new CheckResult("APatch","Not detected",
            "APatch is a kernel-based root solution similar to KernelSU.",
            false, 10);
    }

    private CheckResult checkVerifiedBoot() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","ro.boot.verifiedbootstate"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if (val != null) {
                val = val.trim();
                boolean warn = "orange".equals(val) || "red".equals(val) || "yellow".equals(val);
                return new CheckResult("Verified Boot","State: "+val,
                    "Verified Boot ensures the OS hasn't been tampered with. Orange/Red means modified.",
                    warn, 9);
            }
        } catch (Exception e) {}
        return new CheckResult("Verified Boot","Could not determine",
            "Verified Boot ensures the OS hasn't been tampered with. Orange/Red means modified.",
            false, 9);
    }

    private CheckResult checkKnox() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","ro.boot.warranty_bit"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if ("0x1".equals(val!=null?val.trim():"") || "1".equals(val!=null?val.trim():""))
                return new CheckResult("Knox Status","Knox warranty void: "+val.trim(),
                    "Samsung Knox warranty bit is tripped when root is attempted. Cannot be reset.",
                    true, 8);
        } catch (Exception e) {}
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","ro.knox.fuse_status"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if (val != null && !val.trim().isEmpty() && !"0".equals(val.trim()))
                return new CheckResult("Knox Status","Knox fuse: "+val.trim(),
                    "Samsung Knox warranty bit is tripped when root is attempted. Cannot be reset.",
                    true, 8);
        } catch (Exception e) {}
        return new CheckResult("Knox Status","Knox not tripped or not Samsung",
            "Samsung Knox warranty bit is tripped when root is attempted. Cannot be reset.",
            false, 8);
    }

    private CheckResult checkAntiRollback() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","ro.boot.avb_version"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            boolean hasArp = val != null && !val.trim().isEmpty();
            return new CheckResult("Anti-Rollback Protection",
                hasArp ? "AVB version: "+val.trim() : "Not detected",
                "Anti-rollback protection prevents downgrading to vulnerable older OS versions.",
                !hasArp, 5);
        } catch (Exception e) {}
        return new CheckResult("Anti-Rollback Protection","Could not determine",
            "Anti-rollback protection prevents downgrading to vulnerable older OS versions.",
            false, 5);
    }

    private CheckResult checkTreble() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","ro.treble.enabled"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            boolean treble = "true".equals(val!=null?val.trim():"");
            return new CheckResult("Treble Support",
                treble ? "Project Treble enabled" : "Treble not enabled",
                "Project Treble separates vendor implementation from Android OS for faster updates.",
                !treble, 3);
        } catch (Exception e) {}
        return new CheckResult("Treble Support","Could not determine",
            "Project Treble separates vendor implementation from Android OS for faster updates.",
            false, 3);
    }

    private CheckResult checkNativeRoot() {
        try {
            Process proc = Runtime.getRuntime().exec(
                new String[]{"/system/bin/sh","-c","cat /proc/self/status | grep CapEff"});
            BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line = br.readLine(); br.close(); proc.destroy();
            if (line != null && line.contains("CapEff")) {
                String hex = line.replaceAll("[^0-9a-fA-F]","").trim();
                if (!hex.isEmpty()) {
                    long caps = Long.parseLong(hex, 16);
                    boolean hasRoot = (caps & 0x1) != 0;
                    return new CheckResult("Native Capability Check",
                        "CapEff: "+hex,
                        "Checks Linux capabilities directly. CAP_CHOWN set indicates root-level privileges.",
                        hasRoot, 10);
                }
            }
        } catch (Exception e) {}
        return new CheckResult("Native Capability Check","Could not read capabilities",
            "Checks Linux capabilities directly. CAP_CHOWN set indicates root-level privileges.",
            false, 10);
    }
}
