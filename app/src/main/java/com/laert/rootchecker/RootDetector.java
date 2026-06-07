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
        public final boolean detected;
        public CheckResult(String name, String detail, boolean detected) {
            this.name = name;
            this.detail = detail;
            this.detected = detected;
        }
    }

    public CheckResult[] runAllChecks() {
        List results = new ArrayList();
        // Original checks
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
        // New advanced checks
        results.add(checkPlayIntegrity());
        results.add(checkEmulator());
        results.add(checkAdbEnabled());
        results.add(checkDeveloperOptions());
        results.add(checkOTADisabled());
        results.add(checkMagiskDenyList());
        results.add(checkZygiskModules());
        results.add(checkKernelSU());
        results.add(checkAPatch());
        return (CheckResult[]) results.toArray(new CheckResult[results.size()]);
    }

    private CheckResult checkSuBinary() {
        String[] paths = {"/system/bin/su","/system/xbin/su","/sbin/su","/data/local/xbin/su","/data/local/bin/su","/data/local/su","/su/bin/su","/magisk/.core/bin/su"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists()) return new CheckResult("SuperUser Binary","Found at: "+paths[i],true);
        }
        return new CheckResult("SuperUser Binary","Not found in common paths",false);
    }

    private CheckResult checkSuInPath() {
        String path = System.getenv("PATH");
        if (path != null) {
            String[] dirs = path.split(":");
            for (int i = 0; i < dirs.length; i++) {
                if (new File(dirs[i],"su").exists()) return new CheckResult("su in PATH","Found in: "+dirs[i],true);
            }
        }
        return new CheckResult("su in PATH","Not found in PATH",false);
    }

    private CheckResult checkBusybox() {
        String[] paths = {"/system/bin/busybox","/system/xbin/busybox","/sbin/busybox","/su/xbin/busybox"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists()) return new CheckResult("BusyBox Binary","Found at: "+paths[i],true);
        }
        return new CheckResult("BusyBox Binary","Not present",false);
    }

    private CheckResult checkSuperuserApk() {
        String[] paths = {"/system/app/Superuser.apk","/system/app/SuperSU/SuperSU.apk","/system/app/SuperSU.apk","/system/priv-app/Superuser.apk"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists()) return new CheckResult("SuperUser Exists","Found: "+paths[i],true);
        }
        return new CheckResult("SuperUser Exists","Not in system",false);
    }

    private CheckResult checkMagisk() {
        String[] paths = {
            "/sbin/.magisk","/sbin/.core/mirror",
            "/sbin/.core/img","/data/adb/magisk",
            "/data/adb/magisk.db","/magisk",
            "/data/adb/magisk/busybox"
        };
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists()) return new CheckResult("Magisk","Detected: "+paths[i],true);
        }
        return new CheckResult("Magisk","No Magisk artifacts found",false);
    }

    private CheckResult checkZygisk() {
        String[] paths = {
            "/data/adb/modules/.zygisk",
            "/dev/.magisk/zygisk",
            "/system/lib/libzygisk.so",
            "/system/lib64/libzygisk.so"
        };
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists()) return new CheckResult("Zygisk","Detected: "+paths[i],true);
        }
        // Check prop
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/getprop","persist.sys.zygisk"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if ("true".equals(val != null ? val.trim() : "")) {
                return new CheckResult("Zygisk","persist.sys.zygisk=true",true);
            }
        } catch (Exception e) {}
        return new CheckResult("Zygisk","Not detected",false);
    }

    private CheckResult checkMagiskModules() {
        File modulesDir = new File("/data/adb/modules");
        if (modulesDir.exists() && modulesDir.isDirectory()) {
            String[] modules = modulesDir.list();
            if (modules != null && modules.length > 0) {
                return new CheckResult("Magisk Modules",
                    modules.length + " module(s) installed", true);
            }
        }
        return new CheckResult("Magisk Modules","No modules found",false);
    }

    private CheckResult checkKnownRootApps() {
        String[] packages = {
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.alephzain.framaroot"
        };
        for (int i = 0; i < packages.length; i++) {
            if (new File("/data/data/"+packages[i]).exists())
                return new CheckResult("Root Management Apps","Detected: "+packages[i],true);
        }
        return new CheckResult("Root Management Apps","None detected",false);
    }

    private CheckResult checkPotentiallyDangerousApps() {
        String[] packages = {
            "com.chelpus.lackypatch",
            "com.dimonvideo.luckypatcher",
            "com.forpda.lp",
            "com.chelpus.luckypatcher",
            "com.gameguardian.android",
            "catch_.me_.if_.you_.can_",
            "com.android.vending.billing.InAppBillingService.LUCK",
            "com.android.vending.billing.InAppBillingService.LOCK"
        };
        for (int i = 0; i < packages.length; i++) {
            if (new File("/data/data/"+packages[i]).exists())
                return new CheckResult("Potentially Dangerous Apps","Detected: "+packages[i],true);
        }
        return new CheckResult("Potentially Dangerous Apps","None detected",false);
    }

    private CheckResult checkRootCloakingApps() {
        String[] packages = {
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.amphoras.hidemyroot",
            "com.formyhm.hideroot",
            "me.phh.superuser"
        };
        for (int i = 0; i < packages.length; i++) {
            if (new File("/data/data/"+packages[i]).exists())
                return new CheckResult("Root Cloaking Apps","Detected: "+packages[i],true);
        }
        String[] paths = {
            "/data/adb/modules/shamiko",
            "/data/adb/modules/MagiskHide",
            "/data/adb/modules/zygisk_shamiko"
        };
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Root Cloaking Apps","Shamiko/MagiskHide detected",true);
        }
        return new CheckResult("Root Cloaking Apps","None detected",false);
    }

    private CheckResult checkBuildTags() {
        String tags = Build.TAGS;
        if (tags != null && tags.contains("test-keys"))
            return new CheckResult("Test Keys","Signed with test-keys: "+tags,true);
        return new CheckResult("Test Keys","Tags: "+(tags!=null?tags:"null"),false);
    }

    private CheckResult checkTestKeys() {
        String fp = Build.FINGERPRINT;
        boolean suspect = false;
        if (fp != null) {
            String fpl = fp.toLowerCase();
            if (fpl.contains("generic")||fpl.contains("test-keys")||fpl.contains("debug")) suspect = true;
        }
        String display = fp!=null?fp.substring(0,Math.min(60,fp.length())):"null";
        return new CheckResult("Fingerprint Check",display,suspect);
    }

    private CheckResult checkDangerousProps() {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/getprop"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            String found = null;
            while ((line=br.readLine())!=null) {
                if ((line.contains("ro.debuggable")&&line.contains("[1]"))
                    ||(line.contains("ro.secure")&&line.contains("[0]"))
                    ||(line.contains("service.adb.root")&&line.contains("[1]"))) {
                    found=line.trim(); break;
                }
            }
            br.close(); p.destroy();
            if (found!=null) return new CheckResult("Dangerous Props",found,true);
        } catch (Exception e) {}
        return new CheckResult("Dangerous Props","No dangerous system properties",false);
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
                    return new CheckResult("Read/Write Paths","Mounted as: "+opts.split(",")[0],rw);
                }
            }
            br.close();
        } catch (Exception e) {}
        return new CheckResult("Read/Write Paths","Could not determine (likely read-only)",false);
    }

    private CheckResult checkSelinuxEnforcing() {
        try {
            File f = new File("/sys/fs/selinux/enforce");
            if (f.exists()) {
                BufferedReader br = new BufferedReader(new FileReader(f));
                String val = br.readLine(); br.close();
                boolean permissive = "0".equals(val!=null?val.trim():"1");
                return new CheckResult("SELinux Status",permissive?"PERMISSIVE":"Enforcing",permissive);
            }
        } catch (Exception e) {}
        return new CheckResult("SELinux Status","Could not read enforce file",false);
    }

    private CheckResult checkRootNativeTest() {
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"su","-c","id"});
            BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String output = br.readLine(); br.close(); proc.destroy();
            if (output!=null&&output.contains("uid=0"))
                return new CheckResult("Root Native Test",output.substring(0,Math.min(50,output.length())),true);
        } catch (Exception e) {}
        return new CheckResult("Root Native Test","su command failed or denied",false);
    }

    private CheckResult checkWritableSystem() {
        File testFile = new File("/system/.rootcheck_test");
        try {
            boolean created = testFile.createNewFile();
            if (created) { testFile.delete(); return new CheckResult("Writable /system","/system is writable",true); }
        } catch (Exception e) {}
        return new CheckResult("Writable /system","/system is not writable",false);
    }

    private CheckResult checkHiddenSuBinaries() {
        String[] paths = {"/system/bin/.ext/.su","/system/usr/we-need-root/su-backup","/system/xbin/mu"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Hidden su Binaries","Found: "+paths[i],true);
        }
        return new CheckResult("Hidden su Binaries","None found",false);
    }

    private CheckResult checkXposed() {
        String[] paths = {"/system/framework/XposedBridge.jar","/system/lib/libxposed_art.so","/data/data/de.robv.android.xposed.installer"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("Xposed Framework","Detected: "+paths[i],true);
        }
        try {
            throw new Exception("probe");
        } catch (Exception e) {
            StackTraceElement[] stack = e.getStackTrace();
            for (int i = 0; i < stack.length; i++) {
                if (stack[i].getClassName().contains("XposedBridge"))
                    return new CheckResult("Xposed Framework","Found in stack trace",true);
            }
        }
        return new CheckResult("Xposed Framework","Not detected",false);
    }

    private CheckResult checkPlayIntegrity() {
        // Check for indicators that Play Integrity would fail
        String tags = Build.TAGS;
        String fp = Build.FINGERPRINT;
        String type = Build.TYPE;
        boolean fail = false;
        String reason = "";
        if (tags != null && tags.contains("test-keys")) {
            fail = true; reason = "test-keys build";
        } else if ("eng".equals(type) || "userdebug".equals(type)) {
            fail = true; reason = "Build type: " + type;
        } else if (fp != null && (fp.contains("generic") || fp.contains("unknown"))) {
            fail = true; reason = "Generic fingerprint";
        } else if (new File("/data/adb/magisk").exists()) {
            fail = true; reason = "Magisk detected";
        }
        if (fail) {
            return new CheckResult("Play Integrity","Likely FAILS: " + reason, true);
        }
        return new CheckResult("Play Integrity","Likely passes (basic check only)", false);
    }

    private CheckResult checkEmulator() {
        boolean isEmulator = false;
        String reason = "";
        if (Build.FINGERPRINT != null && Build.FINGERPRINT.contains("generic")) {
            isEmulator = true; reason = "Generic fingerprint";
        } else if ("goldfish".equals(Build.HARDWARE) || "ranchu".equals(Build.HARDWARE)) {
            isEmulator = true; reason = "Hardware: " + Build.HARDWARE;
        } else if (Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK")) {
            isEmulator = true; reason = "Model: " + Build.MODEL;
        } else if (new File("/dev/socket/qemud").exists()) {
            isEmulator = true; reason = "QEMU socket found";
        } else if (new File("/dev/qemu_pipe").exists()) {
            isEmulator = true; reason = "QEMU pipe found";
        }
        return new CheckResult("Emulator Detection",
            isEmulator ? reason : "Real device detected", isEmulator);
    }

    private CheckResult checkAdbEnabled() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","persist.service.adb.enable"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if ("1".equals(val != null ? val.trim() : "")) {
                return new CheckResult("ADB Status","ADB is enabled",true);
            }
        } catch (Exception e) {}
        return new CheckResult("ADB Status","ADB not enabled via prop",false);
    }

    private CheckResult checkDeveloperOptions() {
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","persist.sys.usb.config"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if (val != null && val.contains("adb")) {
                return new CheckResult("Developer Options","USB config: "+val.trim(),true);
            }
        } catch (Exception e) {}
        return new CheckResult("Developer Options","ADB not in USB config",false);
    }

    private CheckResult checkOTADisabled() {
        String[] paths = {
            "/cache/recovery",
            "/data/cache/recovery"
        };
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","ro.ota.disable"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if ("1".equals(val != null ? val.trim() : "") ||
                "true".equals(val != null ? val.trim() : "")) {
                return new CheckResult("OTA Updates","OTA updates disabled",true);
            }
        } catch (Exception e) {}
        return new CheckResult("OTA Updates","OTA updates enabled",false);
    }

    private CheckResult checkMagiskDenyList() {
        File denyList = new File("/data/adb/magisk/deny");
        if (denyList.exists()) {
            return new CheckResult("Magisk DenyList","DenyList database found",true);
        }
        File denyDb = new File("/data/adb/magisk/denylist.db");
        if (denyDb.exists()) {
            return new CheckResult("Magisk DenyList","DenyList enabled",true);
        }
        return new CheckResult("Magisk DenyList","Not detected",false);
    }

    private CheckResult checkZygiskModules() {
        File zygiskDir = new File("/data/adb/modules");
        if (zygiskDir.exists() && zygiskDir.isDirectory()) {
            File[] modules = zygiskDir.listFiles();
            if (modules != null) {
                for (int i = 0; i < modules.length; i++) {
                    File zygisk = new File(modules[i], "zygisk");
                    if (zygisk.exists()) {
                        return new CheckResult("Zygisk Modules",
                            "Zygisk module: " + modules[i].getName(), true);
                    }
                }
            }
        }
        return new CheckResult("Zygisk Modules","No Zygisk modules found",false);
    }

    private CheckResult checkKernelSU() {
        String[] paths = {
            "/data/adb/ksud",
            "/data/adb/ksu",
            "/system/bin/ksud"
        };
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("KernelSU","Detected: "+paths[i],true);
        }
        try {
            Process p = Runtime.getRuntime().exec(
                new String[]{"/system/bin/getprop","persist.sys.kernelsu"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String val = br.readLine(); br.close(); p.destroy();
            if (val != null && !val.trim().isEmpty()) {
                return new CheckResult("KernelSU","KernelSU prop detected",true);
            }
        } catch (Exception e) {}
        return new CheckResult("KernelSU","Not detected",false);
    }

    private CheckResult checkAPatch() {
        String[] paths = {
            "/data/adb/ap",
            "/data/adb/apatch",
            "/data/adb/apatch/apatchd"
        };
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists())
                return new CheckResult("APatch","Detected: "+paths[i],true);
        }
        return new CheckResult("APatch","Not detected",false);
    }
}
