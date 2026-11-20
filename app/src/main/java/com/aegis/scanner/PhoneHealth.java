package com.aegis.scanner;

import android.app.ActivityManager;
import android.app.AppOpsManager;
import android.app.usage.StorageStats;
import android.app.usage.StorageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import android.os.storage.StorageManager;
import android.provider.Settings;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Phone check-up: restart reminder, update age, Private DNS, storage, battery, memory and
 * Xiaomi ad/tracking apps. {@link #gather} reads the phone; {@link #judge} turns readings into
 * findings and is pure Java so it can be unit-tested.
 */
public final class PhoneHealth {

    /** Preloaded ad and tracking apps that can be removed for the current user with a computer. */
    static final String[][] AD_APPS = {
            {"com.miui.msa.global", "MIUI System Ads (MSA)"},
            {"com.miui.analytics", "MIUI Analytics"},
            {"com.miui.analytics.go", "MIUI Analytics"},
            {"com.facebook.appmanager", "Facebook App Manager"},
            {"com.facebook.services", "Facebook Services"},
            {"com.facebook.system", "Facebook App Installer"},
    };

    static final String ADGUARD_DNS = "dns.adguard-dns.com";

    // Battery health codes from android.os.BatteryManager, copied so judge() runs in plain-Java unit tests.
    static final int HEALTH_UNKNOWN = 1, HEALTH_GOOD = 2, HEALTH_OVERHEAT = 3, HEALTH_DEAD = 4,
            HEALTH_OVER_VOLTAGE = 5, HEALTH_FAILURE = 6, HEALTH_COLD = 7;

    /** Readings from the phone. Unknown values stay at their defaults. */
    public static final class Inputs {
        public long uptimeMs, now;
        public String securityPatch = "";          // "2026-05-01"
        public boolean privateDnsKnown;
        public String privateDnsName;              // null when off or automatic
        public long freeBytes, totalBytes;
        public int batteryTempTenths = -1, batteryHealth = -1;
        public long memAvail, memTotal;
        public boolean lowMemory;
        public final List<String[]> adApps = new ArrayList<>();   // {package, name}
        /** {label, package, bytes}, biggest first; null when Usage access is off. */
        public List<String[]> bigApps;
    }

    public static List<Finding> judge(Inputs in) {
        List<Finding> out = new ArrayList<>();
        long day = 24L * 3600 * 1000;

        // Restart
        long days = in.uptimeMs / day;
        if (in.uptimeMs > 7 * day) {
            out.add(new Finding(Finding.Level.YELLOW, "Restart", "Restart your phone",
                    "It has been on for " + days + " days. A restart clears memory build-up and often fixes lag "
                            + "and battery drain. Once a week is a good habit."));
        } else if (in.uptimeMs > 3 * day) {
            out.add(new Finding(Finding.Level.INFO, "Restart", "On for " + days + " days",
                    "A restart every week or so keeps the phone smooth."));
        } else {
            out.add(new Finding(Finding.Level.GREEN, "Restart", "Restarted recently",
                    "On for " + (in.uptimeMs < day ? "less than a day" : days + (days == 1 ? " day" : " days")) + "."));
        }

        // Security update
        long patchAge = patchAgeDays(in.securityPatch, in.now);
        if (patchAge >= 0) {
            String when = in.securityPatch + " (" + (patchAge / 30) + " months ago)";
            Finding.Level lvl = patchAge > 180 ? Finding.Level.YELLOW : patchAge > 90 ? Finding.Level.INFO : Finding.Level.GREEN;
            out.add(new Finding(lvl, "Updates",
                    lvl == Finding.Level.GREEN ? "Security update is recent" : "Check for a system update",
                    "Last security patch: " + when + "."
                            + (lvl == Finding.Level.GREEN ? "" : " Updates fix holes that spy apps and malware use."))
                    .action("About phone", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_DEVICE_INFO_SETTINGS));
        }

        // Private DNS
        if (in.privateDnsKnown) {
            if (in.privateDnsName != null && !in.privateDnsName.isEmpty()) {
                out.add(new Finding(Finding.Level.GREEN, "Safe browsing", "Private DNS is on",
                        "Every app looks up websites through " + in.privateDnsName + "."));
            } else {
                out.add(new Finding(Finding.Level.INFO, "Safe browsing", "Block ads and phishing sites in every app",
                        "Set Private DNS to " + ADGUARD_DNS + ". It blocks ad, tracking and phishing sites for the "
                                + "whole phone, with no app or VPN. Website names you visit then go to AdGuard instead "
                                + "of your mobile or Wi-Fi provider.\n\nXiaomi: Settings → Connection & sharing → Private "
                                + "DNS → Private DNS provider hostname → paste.\nOther phones: Settings → Network & "
                                + "internet → Private DNS.")
                        .action("Copy " + ADGUARD_DNS, Finding.ActionType.COPY, ADGUARD_DNS)
                        .action("Open Settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_WIRELESS_SETTINGS));
            }
        }

        // Storage
        if (in.totalBytes > 0) {
            double freePct = 100.0 * in.freeBytes / in.totalBytes;
            Finding.Level lvl = freePct < 5 ? Finding.Level.RED : freePct < 10 ? Finding.Level.YELLOW : Finding.Level.GREEN;
            StringBuilder sb = new StringBuilder(gb(in.freeBytes) + " free of " + gb(in.totalBytes) + ".");
            if (lvl != Finding.Level.GREEN) sb.append(" A nearly full phone gets slow and can fail to update.");
            if (in.bigApps != null && !in.bigApps.isEmpty()) {
                sb.append("\n\nBiggest apps:");
                for (int i = 0; i < Math.min(5, in.bigApps.size()); i++) {
                    String[] a = in.bigApps.get(i);
                    sb.append("\n• ").append(a[0]).append(": ").append(gb(Long.parseLong(a[2])));
                }
            } else if (in.bigApps == null) {
                sb.append("\n\nAllow Usage access to see which apps use the most space.");
            }
            Finding f = new Finding(lvl, "Storage", lvl == Finding.Level.GREEN ? "Plenty of storage" : "Storage is almost full",
                    sb.toString()).action("Storage settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_INTERNAL_STORAGE_SETTINGS);
            if (in.bigApps != null && !in.bigApps.isEmpty()) {
                f.action("App info: " + in.bigApps.get(0)[0], Finding.ActionType.APP_INFO, in.bigApps.get(0)[1]);
            }
            if (in.bigApps == null) f.action("Usage access", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_USAGE_ACCESS_SETTINGS);
            out.add(f);
        }

        // Battery
        if (in.batteryTempTenths >= 0) {
            double t = in.batteryTempTenths / 10.0;
            String temp = String.format(Locale.US, "%.0f°C", t);
            boolean badHealth = in.batteryHealth > 0 && in.batteryHealth != HEALTH_GOOD && in.batteryHealth != HEALTH_UNKNOWN;
            if (t >= 45 || in.batteryHealth == HEALTH_OVERHEAT) {
                out.add(new Finding(Finding.Level.YELLOW, "Battery", "Phone is hot (" + temp + ")",
                        "Close games and the camera, take off the case, and don't charge it under a pillow or in the sun. "
                                + "If it's hot while you're not using it, an app may be running in the background."));
            } else if (badHealth) {
                out.add(new Finding(Finding.Level.YELLOW, "Battery", "Battery needs attention",
                        "Android reports the battery as \"" + healthName(in.batteryHealth) + "\". A service centre can check it."));
            } else {
                out.add(new Finding(t >= 40 ? Finding.Level.INFO : Finding.Level.GREEN, "Battery",
                        t >= 40 ? "Battery is warm (" + temp + ")" : "Battery is healthy",
                        "Temperature " + temp + ", health " + healthName(in.batteryHealth) + ". Turning on battery "
                                + "protection (charge limit) in Battery settings slows wear if you charge overnight.")
                        .action("Battery settings", Finding.ActionType.OPEN_SETTINGS, Intent.ACTION_POWER_USAGE_SUMMARY));
            }
        }

        // Memory
        if (in.memTotal > 0) {
            double availPct = 100.0 * in.memAvail / in.memTotal;
            if (in.lowMemory || availPct < 10) {
                out.add(new Finding(Finding.Level.YELLOW, "Memory", "Memory is low",
                        gb(in.memAvail) + " free of " + gb(in.memTotal) + ". Close apps you aren't using or restart."));
            } else {
                out.add(new Finding(Finding.Level.GREEN, "Memory", "Memory is fine",
                        gb(in.memAvail) + " free of " + gb(in.memTotal) + "."));
            }
        }

        // Ad and tracking apps
        if (!in.adApps.isEmpty()) {
            StringBuilder names = new StringBuilder(), cmds = new StringBuilder(), undo = new StringBuilder();
            for (String[] a : in.adApps) {
                names.append("\n• ").append(a[1]).append(" (").append(a[0]).append(")");
                cmds.append("adb shell pm uninstall --user 0 ").append(a[0]).append('\n');
                undo.append("adb shell cmd package install-existing ").append(a[0]).append('\n');
            }
            out.add(new Finding(Finding.Level.INFO, "Ads & tracking", in.adApps.size() + " ad or tracking app(s) built in",
                    "These came with the phone and show ads or send usage data:" + names
                            + "\n\nWithout a computer: Settings → Passwords & security → Privacy → Ad services → turn off "
                            + "personalised ads.\nWith a computer (USB debugging), you can remove them for your account "
                            + "with the copied commands, and bring any back with the restore commands.")
                    .action("Copy remove commands", Finding.ActionType.COPY, cmds.toString().trim())
                    .action("Copy restore commands", Finding.ActionType.COPY, undo.toString().trim()));
        }

        Collections.sort(out, (a, b) -> a.level.ordinal() - b.level.ordinal());
        return out;
    }

    static long patchAgeDays(String patch, long now) {
        try {
            SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            f.setLenient(false);
            return (now - f.parse(patch).getTime()) / (24L * 3600 * 1000);
        } catch (Exception e) {
            return -1;
        }
    }

    static String gb(long bytes) {
        double g = bytes / 1e9;
        return g >= 10 ? String.format(Locale.US, "%.0f GB", g)
                : g >= 1 ? String.format(Locale.US, "%.1f GB", g)
                : String.format(Locale.US, "%.0f MB", bytes / 1e6);
    }

    private static String healthName(int h) {
        switch (h) {
            case HEALTH_GOOD: return "good";
            case HEALTH_OVERHEAT: return "overheating";
            case HEALTH_DEAD: return "worn out";
            case HEALTH_OVER_VOLTAGE: return "over voltage";
            case HEALTH_COLD: return "too cold";
            case HEALTH_FAILURE: return "failure";
            default: return "unknown";
        }
    }

    // ------------------------------------------------------------------ reading the phone

    /** Reads everything. Call from a background thread: sizing apps can take a few seconds. */
    @SuppressWarnings("deprecation")
    public static Inputs gather(Context ctx) {
        Inputs in = new Inputs();
        in.now = System.currentTimeMillis();
        in.uptimeMs = SystemClock.elapsedRealtime();
        in.securityPatch = Build.VERSION.SECURITY_PATCH == null ? "" : Build.VERSION.SECURITY_PATCH;

        try {
            ConnectivityManager cm = ctx.getSystemService(ConnectivityManager.class);
            Network n = cm == null ? null : cm.getActiveNetwork();
            LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
            if (lp != null && Build.VERSION.SDK_INT >= 28) {
                in.privateDnsKnown = true;
                in.privateDnsName = lp.getPrivateDnsServerName();
            }
        } catch (Exception ignored) { }

        try {
            StatFs fs = new StatFs(Environment.getDataDirectory().getPath());
            in.freeBytes = fs.getAvailableBytes();
            in.totalBytes = fs.getTotalBytes();
        } catch (Exception ignored) { }

        Intent b = ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (b != null) {
            in.batteryTempTenths = b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);
            in.batteryHealth = b.getIntExtra(BatteryManager.EXTRA_HEALTH, -1);
        }

        ActivityManager am = ctx.getSystemService(ActivityManager.class);
        if (am != null) {
            ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
            am.getMemoryInfo(mi);
            in.memAvail = mi.availMem;
            in.memTotal = mi.totalMem;
            in.lowMemory = mi.lowMemory;
        }

        PackageManager pm = ctx.getPackageManager();
        for (String[] a : AD_APPS) {
            try {
                if (pm.getApplicationInfo(a[0], 0).enabled) in.adApps.add(a);
            } catch (PackageManager.NameNotFoundException notThere) { /* removed or never installed */ }
        }

        in.bigApps = bigApps(ctx, pm);
        return in;
    }

    /** Apps of 500 MB or more by app + data size, biggest first. Null without Usage access. */
    private static List<String[]> bigApps(Context ctx, PackageManager pm) {
        try {
            AppOpsManager ops = ctx.getSystemService(AppOpsManager.class);
            int mode = Build.VERSION.SDK_INT >= 29
                    ? ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), ctx.getPackageName())
                    : ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), ctx.getPackageName());
            if (mode != AppOpsManager.MODE_ALLOWED) return null;
            StorageStatsManager ssm = ctx.getSystemService(StorageStatsManager.class);
            List<String[]> out = new ArrayList<>();
            for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
                try {
                    StorageStats s = ssm.queryStatsForPackage(StorageManager.UUID_DEFAULT, ai.packageName, android.os.Process.myUserHandle());
                    long total = s.getAppBytes() + s.getDataBytes();
                    if (total < 500_000_000L) continue;
                    String label;
                    try { label = pm.getApplicationLabel(ai).toString(); } catch (Exception e) { label = ai.packageName; }
                    out.add(new String[]{label, ai.packageName, String.valueOf(total)});
                } catch (Exception ignored) { }
            }
            Collections.sort(out, (x, y) -> Long.compare(Long.parseLong(y[2]), Long.parseLong(x[2])));
            return out;
        } catch (Exception e) {
            return null;
        }
    }
}
