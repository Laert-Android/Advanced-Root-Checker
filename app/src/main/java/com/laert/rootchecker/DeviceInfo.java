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
        InfoItem[] items = new InfoItem[20];
        items[0] = getManufacturer();
        items[1] = getBrand();
        items[2] = getModel();
        items[3] = getBoard();
        items[4] = getHardware();
        items[5] = getAndroidID(ctx);
        items[6] = getBootloader();
        items[7] = getUserHost();
        items[8] = getAndroidVersion();
        items[9] = getSecurityPatch();
        items[10] = getBuildType();
        items[11] = getScreenLock(ctx);
        items[12] = getSelinux();
        items[13] = getCpuArch();
        items[14] = getKernelVersion();
        items[15] = getFingerprint();
        items[16] = getUser();
        items[17] = getHost();
        items[18] = getDisplay();
        items[19] = getDevice();
        return items;
    }

    private static InfoItem getManufacturer() {
        String val = Build.MANUFACTURER;
        if (val == null || val.isEmpty()) val = "Unknown";
        return new InfoItem("Manufacturer", val, false);
    }

    private static InfoItem getBrand() {
        String val = Build.BRAND;
        if (val == null || val.isEmpty()) val = "Unknown";
        return new InfoItem("Brand", val, false);
    }

    private static InfoItem getModel() {
        String val = Build.MODEL;
        if (val == null || val.isEmpty()) val = "Unknown";
        return new InfoItem("Model", val, false);
    }

    private static InfoItem getBoard() {
        String val = Build.BOARD;
        if (val == null || val.isEmpty()) val = "Unknown";
        return new InfoItem("Board", val, false);
    }

    private static InfoItem getHardware() {
        String val = Build.HARDWARE;
        if (val == null || val.isEmpty()) val = "Unknown";
        boolean warn = "goldfish".equals(val) || "ranchu".equals(val);
        return new InfoItem("Hardware", val, warn);
    }

    private static InfoItem getAndroidID(Context ctx) {
        String val = "Unknown";
        try {
            val = android.provider.Settings.Secure.getString(
                    ctx.getContentResolver(),
                    android.provider.Settings.Secure.ANDROID_ID);
            if (val == null || val.isEmpty()) val = "Unknown";
        } catch (Exception e) {}
        return new InfoItem("Android ID", val, false);
    }

    private static InfoItem getBootloader() {
        String val = Build.BOOTLOADER;
        if (val == null || val.isEmpty()) val = "Unknown";
        boolean warn = val.toLowerCase().contains("unlocked");
        return new InfoItem("Bootloader", val, warn);
    }

    private static InfoItem getUserHost() {
        String user = Build.USER;
        String host = Build.HOST;
        if (user == null) user = "Unknown";
        if (host == null) host = "Unknown";
        boolean warn = "root".equals(user) || user.contains("android-build") == false;
        return new InfoItem("User @ Host", user + " @ " + host, warn);
    }

    private static InfoItem getUser() {
        String val = Build.USER;
        if (val == null || val.isEmpty()) val = "Unknown";
        boolean warn = "root".equals(val);
        return new InfoItem("User", val, warn);
    }

    private static InfoItem getHost() {
        String val = Build.HOST;
        if (val == null || val.isEmpty()) val = "Unknown";
        return new InfoItem("Host", val, false);
    }

    private static InfoItem getDisplay() {
        String val = Build.DISPLAY;
        if (val == null || val.isEmpty()) val = "Unknown";
        return new InfoItem("Display", val, false);
    }

    private static InfoItem getDevice() {
        String val = Build.DEVICE;
        if (val == null || val.isEmpty()) val = "Unknown";
        return new InfoItem("Device", val, false);
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

    private static InfoItem getScreenLock(Context ctx) {
        try {
            KeyguardManager km = (KeyguardManager)
                    ctx.getSystemService(Context.KEYGUARD_SERVICE);
            boolean secure = false;
            if (android.os.Build.VERSION.SDK_INT >= 23) {
                secure = km != null && km.isDeviceSecure();
            } else {
                secure = km != null && km.isKeyguardSecure();
            }
            return new InfoItem("Screen Lock",
                    secure ? "Enabled" : "Not set", !secure);
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