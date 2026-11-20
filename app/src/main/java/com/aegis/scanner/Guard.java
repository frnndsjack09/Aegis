package com.aegis.scanner;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.ChangedPackages;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.provider.Settings;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * New-app alerts: checks every app installed or updated since the last check and posts a notification
 * when one is risky. Runs every ~15 minutes as a background job, and instantly while scam alerts
 * (the notification listener) are on. Uses Android's changed-packages list, so nothing runs in between.
 */
public final class Guard {

    static final String CHANNEL = "alerts";
    static final String PREF_ON = "guard_on";
    private static final int JOB_ID = 7;

    private Guard() { }

    public static boolean isOn(Context ctx) {
        return prefs(ctx).getBoolean(PREF_ON, false);
    }

    /** Turns the background check on or off. Turning on records the current state so only later installs alert. */
    public static void setOn(Context ctx, boolean on) {
        prefs(ctx).edit().putBoolean(PREF_ON, on).apply();
        JobScheduler js = (JobScheduler) ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null) return;
        if (!on) { js.cancel(JOB_ID); return; }
        baseline(ctx);
        schedule(ctx);
    }

    static void schedule(Context ctx) {
        JobScheduler js = (JobScheduler) ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null || js.getPendingJob(JOB_ID) != null) return;
        js.schedule(new JobInfo.Builder(JOB_ID, new ComponentName(ctx, GuardJob.class))
                .setPeriodic(15 * 60 * 1000L)
                .setPersisted(true) // survives reboots (needs RECEIVE_BOOT_COMPLETED)
                .build());
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(Scanner.PREFS, Context.MODE_PRIVATE);
    }

    private static int bootCount(Context ctx) {
        try { return Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.BOOT_COUNT); }
        catch (Exception e) { return -1; }
    }

    private static void baseline(Context ctx) {
        ChangedPackages cp = ctx.getPackageManager().getChangedPackages(0);
        prefs(ctx).edit()
                .putInt("guard_seq", cp == null ? 0 : cp.getSequenceNumber())
                .putInt("guard_boot", bootCount(ctx))
                .apply();
    }

    /** Checks everything installed or updated since the last call. Call from a background thread. */
    public static synchronized void checkChanged(Context ctx) {
        if (!isOn(ctx)) return;
        SharedPreferences p = prefs(ctx);
        // The sequence number restarts at every reboot, so start from 0 after one.
        int boot = bootCount(ctx);
        int seq = p.getInt("guard_boot", -2) == boot ? p.getInt("guard_seq", 0) : 0;
        ChangedPackages cp = ctx.getPackageManager().getChangedPackages(seq);
        if (cp == null) return;
        p.edit().putInt("guard_seq", cp.getSequenceNumber()).putInt("guard_boot", boot).apply();
        checkPackages(ctx, cp.getPackageNames());
    }

    static synchronized void checkPackages(Context ctx, List<String> names) {
        if (!isOn(ctx) || names == null || names.isEmpty()) return;
        SharedPreferences p = prefs(ctx);
        Set<String> seen = new HashSet<>(p.getStringSet("guard_seen", new HashSet<>()));
        Set<String> trusted = p.getStringSet("trusted", new HashSet<>());
        IocDb ioc = null;
        for (String pkg : names) {
            if (pkg.equals(ctx.getPackageName()) || trusted.contains(pkg)) continue;
            PackageInfo pi;
            try {
                pi = ctx.getPackageManager().getPackageInfo(pkg, PackageManager.GET_PERMISSIONS
                        | PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS | ApkCheck.sigFlag());
            } catch (PackageManager.NameNotFoundException removed) {
                continue;
            }
            String key = pkg + "@" + pi.lastUpdateTime;
            if (seen.contains(key)) continue;
            seen.add(key);
            if (ioc == null) ioc = IocDb.load(ctx);
            Alert a = assess(ctx, pi, ioc);
            if (a != null) notify(ctx, pkg.hashCode(), a.title, a.text, appInfoIntent(ctx, pkg), pkg);
        }
        if (seen.size() > 300) seen.clear(); // keeps prefs small; worst case one repeat alert
        p.edit().putStringSet("guard_seen", seen).apply();
    }

    /**
     * Full scan once a week while new-app alerts are on, so problems turn up even if you never open Aegis.
     * Skipped on a low battery. Notifies only when something needs you now.
     */
    static synchronized void weeklyScan(Context ctx) {
        if (!isOn(ctx)) return;
        long last = prefs(ctx).getLong("snap_time", 0);
        if (System.currentTimeMillis() - last < 7L * 24 * 3600 * 1000) return;
        Intent bat = ctx.registerReceiver(null, new android.content.IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (bat != null) {
            int level = bat.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, 100);
            int scale = Math.max(1, bat.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, 100));
            boolean plugged = bat.getIntExtra(android.os.BatteryManager.EXTRA_PLUGGED, 0) != 0;
            if (!plugged && level * 100 / scale < 30) return;
        }
        List<Finding> found = new Scanner(ctx, IocDb.load(ctx)).run((msg, pct) -> { });
        int red = 0;
        String first = null;
        for (Finding f : found) if (f.level == Finding.Level.RED) { red++; if (first == null) first = f.title; }
        if (red == 0) return;
        Intent open = new Intent(ctx, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        notify(ctx, 7007, "Weekly scan: " + (red == 1 ? "1 thing needs" : red + " things need") + " you now",
                first + (red > 1 ? " and " + (red - 1) + " more." : ".") + " Open Aegis and run a scan to see what to do.",
                PendingIntent.getActivity(ctx, 7007, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT), null);
    }

    static final class Alert { String title, text; }

    /** Returns an alert for a risky app, or null if it looks fine. */
    static Alert assess(Context ctx, PackageInfo pi, IocDb ioc) {
        ApplicationInfo ai = pi.applicationInfo;
        if (ai == null || (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) return null;
        PackageManager pm = ctx.getPackageManager();
        ApkCheck.Facts f = new ApkCheck.Facts();
        f.parsed = true;
        f.pkg = pi.packageName;
        try { f.label = pm.getApplicationLabel(ai).toString(); } catch (Exception e) { f.label = f.pkg; }
        ApkCheck.fill(f, pi);
        ApkCheck.matchIoc(f, ioc, pm);

        Alert a = new Alert();
        if (f.iocFamily != null) {
            a.title = "Act now: spy app installed (" + f.label + ")";
            a.text = "\"" + f.label + "\" matches the " + f.iocHow + " of \"" + f.iocFamily + "\", a known spy app or "
                    + "malware. Open Aegis and run a scan. If someone may have installed it to watch you, get help first (1930).";
            return a;
        }
        String remote = Scanner.REMOTE_APPS.get(f.pkg);
        if (remote != null) {
            a.title = "Remote-control app installed: " + remote;
            a.text = "It lets another person see and control your phone. If a caller asked you to install it, "
                    + "uninstall it now, don't open your bank or UPI apps, and call 1930.";
            return a;
        }
        String installer = Scanner.installerOf(pm, f.pkg);
        boolean sideloaded = pi.firstInstallTime >= Scanner.FACTORY_CUTOFF && !Scanner.fromStoreSource(pm, f.pkg)
                && (installer == null || !Scanner.STORES.contains(installer));
        String fake = BankApps.fakeReason(f.label, f.pkg, !sideloaded);
        if (fake != null) {
            a.title = "Act now: possible fake bank app (" + f.label + ")";
            a.text = fake + " Don't open it or type anything into it. Uninstall it.";
            return a;
        }
        if (!sideloaded) return null;
        ApkCheck.Verdict v = ApkCheck.judge(f);
        if (v.level == Finding.Level.GREEN) return null;
        a.title = (v.level == Finding.Level.RED ? "Risky app installed: " : "Check this new app: ") + f.label;
        StringBuilder sb = new StringBuilder("Installed from a file, not an app store.");
        for (String r : v.reasons) sb.append("\n• ").append(r);
        a.text = sb.toString();
        return a;
    }

    private static PendingIntent appInfoIntent(Context ctx, String pkg) {
        Intent i = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + pkg))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        return PendingIntent.getActivity(ctx, pkg.hashCode(), i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    static void ensureChannel(Context ctx) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm != null && nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "Security alerts", NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("Risky new apps and scam messages");
            nm.createNotificationChannel(ch);
        }
    }

    static boolean canNotify(Context ctx) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        return nm != null && nm.areNotificationsEnabled();
    }

    /** Posts a high-priority alert. uninstallPkg adds an Uninstall button (null for none). */
    static void notify(Context ctx, int id, String title, String text, PendingIntent tap, String uninstallPkg) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm == null || !nm.areNotificationsEnabled()) return;
        ensureChannel(ctx);
        Notification.Builder b = new Notification.Builder(ctx, CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_shield)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setCategory(Notification.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(tap);
        if (uninstallPkg != null) {
            Intent del = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + uninstallPkg)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            b.addAction(new Notification.Action.Builder(null, "Uninstall",
                    PendingIntent.getActivity(ctx, ~uninstallPkg.hashCode(), del,
                            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT)).build());
        }
        nm.notify(id, b.build());
    }
}
