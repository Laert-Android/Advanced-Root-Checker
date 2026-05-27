package com.laert.rootchecker;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public class DeviceInfo {

    public static class InfoItem {
        public final String label;
        public final String value;
        public final boolean isWarning;

        public InfoItem(String label, String value, boolean isWarning) {
            this.label = label;
            this.value = value;
            this.isWarning = isWarning;
        }
    }

    public static InfoItem[] getDeviceInfo(Context ctx) {
        InfoItem[] items = new InfoItem[10];
        items[0] = getDeviceModel();
        items[1] = getAndroidVersion();
        items[2] = getSecurityPatch();
        items[3] = getBuildType();
        items[4] = getBootloader();
        items[5] = getScreenLock(ctx);
        items[6] = getSelinux();
        items[7] = getCpuArch();
        items[8] = getKernelVersion();
        items[9] = getFingerprint();
        return items;
    }

    private static InfoItem getDeviceModel() {
        String model = Build.MANUFACTURER + " " + Build.MODEL;
        return new InfoItem("Device", model, false);
    }

    private static InfoItem getAndroidVersion() {
        String ver = "Android " + Build.VERSION.RELEASE +
            " (API " + Build.VERSION.SDK_INT + ")";
        boolean old = Build.VERSION.SDK_INT < 29;
        return new InfoItem("Android Version", ver, old);
    }

    private static InfoItem getSecurityPatch() {
        String patch = "Unknown";
        if (Build.VERSION.SDK_INT >= 23) {
            patch = Build.VERSION.SECURITY_PATCH;
        }
        boolean old = false;
        try {
            int y = Integer.parseInt(patch.substring(0, 4));
            old = y < 2023;
        } catch (Exception e) {}
        return new InfoItem("Security Patch", patch, old);
    }

    private static InfoItem getBuildType() {
        String type = Build.TYPE;
        boolean warn = "eng".equals(type) || "userdebug".equals(type);
        return new InfoItem("Build Type", type, warn);
    }

    private static InfoItem getBootloader() {
        String bl = Build.BOOTLOADER;
        if (bl == null || bl.isEmpty()) bl = "Unknown";
        boolean warn = bl.toLowerCase().contains("unlocked");
        return new InfoItem("Bootloader", bl, warn);
    }

    private static InfoItem getScreenLock(Context ctx) {
        try {
            KeyguardManager km = (KeyguardManager)
                ctx.getSystemService(Context.KEYGUARD_SERVICE);
            boolean secure = km != null && km.isDeviceSecure();
            return new InfoItem("Screen Lock", secure ? "Enabled" : "Not set", !secure);
        } catch (Exception e) {}
        return new InfoItem("Screen Lock", "Unknown", false);
    }

    private static InfoItem getSelinux() {
        try {
            File f = new File("/sys/fs/selinux/enforce");
            if (f.exists()) {
                BufferedReader br = new BufferedReader(new FileReader(f));
                String val = br.readLine();
                br.close();
                boolean enforcing = "1".equals(val != null ? val.trim() : "0");
                return new InfoItem("SELinux",
                    enforcing ? "Enforcing" : "Permissive", !enforcing);
            }
        } catch (Exception e) {}
        return new InfoItem("SELinux", "Unknown", false);
    }

    private static InfoItem getCpuArch() {
        String[] abis = Build.SUPPORTED_ABIS;
        String arch = (abis != null && abis.length > 0) ? abis[0] : "Unknown";
        return new InfoItem("CPU Architecture", arch, false);
    }

    private static InfoItem getKernelVersion() {
        try {
            BufferedReader br = new BufferedReader(
                new FileReader("/proc/version"));
            String line = br.readLine();
            br.close();
            if (line != null && line.length() > 45) {
                line = line.substring(0, 45) + "...";
            }
            return new InfoItem("Kernel", line != null ? line : "Unknown", false);
        } catch (Exception e) {}
        return new InfoItem("Kernel", "Unknown", false);
    }

    private static InfoItem getFingerprint() {
        String fp = Build.FINGERPRINT;
        if (fp == null) fp = "Unknown";
        boolean warn = fp.contains("test-keys") ||
            fp.contains("generic") ||
            fp.toLowerCase().contains("debug");
        if (fp.length() > 45) fp = fp.substring(0, 45) + "...";
        return new InfoItem("Build Fingerprint", fp, warn);
    }
}
