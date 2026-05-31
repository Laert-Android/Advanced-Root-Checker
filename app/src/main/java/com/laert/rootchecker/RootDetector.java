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
        results.add(checkSuBinary());
        results.add(checkSuInPath());
        results.add(checkBusybox());
        results.add(checkSuperuserApk());
        results.add(checkMagisk());
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
        String[] paths = {"/sbin/.magisk","/sbin/.core/mirror","/sbin/.core/img","/data/adb/magisk","/data/adb/modules","/magisk"};
        for (int i = 0; i < paths.length; i++) {
            if (new File(paths[i]).exists()) return new CheckResult("Magisk","Detected: "+paths[i],true);
        }
        return new CheckResult("Magisk","No Magisk artifacts found",false);
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
            "com.android.vending.billing.InAppBillingService.LUCK",
            "com.android.vending.billing.InAppBillingService.LOCK",
            "com.android.vending.billing.InAppBillingService.CRAC",
            "com.android.vending.billing.InAppBillingService.COIN",
            "com.chelpus.luckypatcher",
            "com.nicehash.excavator",
            "com.zhiqupk.root.global",
            "com.gameguardian.android",
            "catch_.me_.if_.you_.can_"
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
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.formyhm.hideroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "me.phh.superuser"
        };
        for (int i = 0; i < packages.length; i++) {
            if (new File("/data/data/"+packages[i]).exists())
                return new CheckResult("Root Cloaking Apps","Detected: "+packages[i],true);
        }
        // Check for MagiskHide/Shamiko
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
}
