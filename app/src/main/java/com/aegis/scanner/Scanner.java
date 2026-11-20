package com.aegis.scanner;

import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.os.Build;
import android.provider.Settings;
import android.text.format.DateUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The main phone scan. Runs on a background thread and returns a list of findings.
 * Uses only public Android APIs, so it works on any Android 8+ phone without root.
 */
public class Scanner {

    public interface Progress { void update(String message, int percent); }

    static final String PREFS = "aegis";

    /** App stores we treat as normal install sources. Anything else counts as "installed from outside a store". */
    static final Set<String> STORES = new HashSet<>(Arrays.asList(
            "com.android.vending",            // Google Play
            "com.xiaomi.market", "com.xiaomi.mipicks", "com.xiaomi.discover", // Xiaomi GetApps
            "com.sec.android.app.samsungapps",  // Galaxy Store
            "com.huawei.appmarket",            // Huawei AppGallery
            "com.heytap.market", "com.oppo.market", // Oppo / Realme / OnePlus
            "com.bbk.appstore", "com.vivo.appstore", // Vivo
            "com.amazon.venezia",              // Amazon
            "org.fdroid.fdroid", "org.fdroid.basic",  // F-Droid
            "com.google.android.feedback",
            "com.facebook.system"               // Facebook App Manager, preloaded; installs Facebook's own apps
    ));

    /** 1 Jan 2009. Preloaded apps report an install time at the 1970 epoch; real installs are far later. */
    static final long FACTORY_CUTOFF = 1230768000000L;

    private static final String[] SYSTEMY_WORDS = {
            "system", "service", "update", "sync", "wifi", "wi-fi", "settings",
            "battery", "security", "google service", "framework", "device", "android"
    };

    static class App {
        String pkg, label, installer, apk;
        boolean system, sideloaded, hidden;
        long updated;
        int uid;
        Set<String> granted = new HashSet<>();
        Set<String> requested = new HashSet<>();
        /** Signing certificates as upper-case SHA-1 and SHA-256 hex (sources use either). */
        List<String> certHashes = new ArrayList<>();
    }

    private final Context ctx;
    private final PackageManager pm;
    private final ContentResolver cr;
    private final SharedPreferences prefs;
    private final IocDb ioc;
    private final Set<String> trusted;

    public final List<Finding> findings = new ArrayList<>();
    public int appsScanned = 0;
    public int userApps = 0;

    public Scanner(Context ctx, IocDb ioc) {
        this.ctx = ctx;
        this.pm = ctx.getPackageManager();
        this.cr = ctx.getContentResolver();
        this.prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        this.ioc = ioc;
        this.trusted = new HashSet<>(prefs.getStringSet("trusted", new HashSet<>()));
    }

    public List<Finding> run(Progress p) {
        p.update("Reading installed apps…", 2);
        List<App> apps = collectApps();
        Map<String, App> byPkg = new HashMap<>();
        for (App a : apps) byPkg.put(a.pkg, a);

        p.update("Checking hidden access (accessibility, admin, notifications)…", 10);
        Set<String> accessibility = enabledAccessibility();
        Set<String> admins = activeAdmins();
        Set<String> notifEnabled = enabledNotificationListeners(); // null = can't read on this phone
        Set<String> notifCapable = servicesFor("android.service.notification.NotificationListenerService");

        p.update("Matching against known spy apps…", 15);
        Set<String> spyHits = checkKnownSpyApps(apps);

        p.update("Checking app files against known spy-app samples…", 20);
        checkApkHashes(apps, spyHits, p);

        p.update("Looking for suspicious behaviour…", 80);
        checkHiddenAccess(apps, byPkg, spyHits, accessibility, admins, notifEnabled, notifCapable);
        Set<String> skip = new HashSet<>(spyHits);
        skip.addAll(checkRemoteAccess(apps, spyHits, accessibility));
        Set<String> cardEmulators = servicesFor("android.nfc.cardemulation.action.HOST_APDU_SERVICE");
        checkSuspicionScore(apps, skip, accessibility, admins, notifEnabled, cardEmulators);
        checkSensitivePermissions(apps, spyHits);

        p.update("Checking for interception (certificates, VPN, proxy)…", 88);
        checkInterception();

        p.update("Checking phone security settings…", 93);
        checkDeviceHealth(byPkg);

        p.update("Comparing with your last scan…", 97);
        checkSnapshot(apps, accessibility, admins);
        addLastUsed();

        Collections.sort(findings, (a, b) -> a.level.ordinal() - b.level.ordinal());
        p.update("Done", 100);
        return findings;
    }

    // ------------------------------------------------------------------ apps

    @SuppressWarnings("deprecation")
    private List<App> collectApps() {
        int flags = PackageManager.GET_PERMISSIONS
                | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES
                                               : PackageManager.GET_SIGNATURES);
        List<PackageInfo> infos;
        try {
            infos = pm.getInstalledPackages(flags);
        } catch (Exception e) {
            // Rare: too much data in one call. Retry without permissions/signatures.
            infos = pm.getInstalledPackages(0);
        }

        Set<String> launchable = new HashSet<>();
        Intent launcher = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        for (ResolveInfo ri : pm.queryIntentActivities(launcher, 0)) {
            launchable.add(ri.activityInfo.packageName);
        }

        List<App> apps = new ArrayList<>();
        for (PackageInfo pi : infos) {
            if (pi.applicationInfo == null || pi.packageName.equals(ctx.getPackageName())) continue;
            App a = new App();
            a.pkg = pi.packageName;
            ApplicationInfo ai = pi.applicationInfo;
            a.system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            try { a.label = pm.getApplicationLabel(ai).toString(); } catch (Exception e) { a.label = a.pkg; }
            a.apk = ai.sourceDir;
            a.uid = ai.uid;
            a.updated = pi.lastUpdateTime;
            a.installer = installerOf(pm, a.pkg);
            // Phone makers (e.g. Xiaomi) preload removable apps like the Screen Recorder outside /system.
            // They have no installer and often no icon, but their install time is the factory epoch (1970).
            boolean factory = pi.firstInstallTime < FACTORY_CUTOFF;
            a.sideloaded = !a.system && !factory && !fromStoreSource(pm, a.pkg)
                    && (a.installer == null || !STORES.contains(a.installer));
            a.hidden = !a.system && !factory && !launchable.contains(a.pkg);

            if (pi.requestedPermissions != null) {
                for (int i = 0; i < pi.requestedPermissions.length; i++) {
                    String perm = pi.requestedPermissions[i];
                    a.requested.add(perm);
                    if (pi.requestedPermissionsFlags != null && i < pi.requestedPermissionsFlags.length
                            && (pi.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                        a.granted.add(perm);
                    }
                }
            }
            for (Signature s : signaturesOf(pi)) {
                a.certHashes.add(sha1(s.toByteArray()));
                a.certHashes.add(sha256(s.toByteArray()));
            }
            apps.add(a);
            if (!a.system) userApps++;
        }
        appsScanned = apps.size();
        return apps;
    }

    @SuppressWarnings("deprecation")
    private Signature[] signaturesOf(PackageInfo pi) {
        try {
            if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null) {
                return pi.signingInfo.hasMultipleSigners()
                        ? pi.signingInfo.getApkContentsSigners()
                        : pi.signingInfo.getSigningCertificateHistory();
            }
            if (pi.signatures != null) return pi.signatures;
        } catch (Exception ignored) { }
        return new Signature[0];
    }

    /**
     * Android 13+ records where an app came from. True when it says a store, or when the installer's name is
     * hidden and no source was recorded: that's what a store-installed app looks like after the store itself was
     * removed (e.g. Xiaomi GetApps or Facebook App Installer debloated). ADB installs record "other" and file
     * installs record "downloaded/local file", so those still count as sideloads.
     */
    static boolean fromStoreSource(PackageManager pm, String pkg) {
        if (Build.VERSION.SDK_INT < 33) return false;
        try {
            android.content.pm.InstallSourceInfo s = pm.getInstallSourceInfo(pkg);
            int src = s.getPackageSource();
            return src == android.content.pm.PackageInstaller.PACKAGE_SOURCE_STORE
                    || (s.getInstallingPackageName() == null
                        && src == android.content.pm.PackageInstaller.PACKAGE_SOURCE_UNSPECIFIED);
        } catch (Exception e) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    static String installerOf(PackageManager pm, String pkg) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                return pm.getInstallSourceInfo(pkg).getInstallingPackageName();
            }
            return pm.getInstallerPackageName(pkg);
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ known spy apps

    private Set<String> checkKnownSpyApps(List<App> apps) {
        // Some spy-app samples were signed with Android's public test keys, which also sign built-in
        // system parts (e.g. com.android.cts.priv.ctsshim). A certificate that signs this phone's own
        // system apps can't identify a spy app, so skip those; package and file-hash matches still apply.
        Set<String> systemCerts = new HashSet<>();
        for (App a : apps) if (a.system) systemCerts.addAll(a.certHashes);

        Set<String> hits = new HashSet<>();
        for (App a : apps) {
            String fam = ioc.packages.get(a.pkg);
            String how = "package name";
            if (fam == null) {
                for (String c : a.certHashes) {
                    if (systemCerts.contains(c)) continue;
                    fam = ioc.certs.get(c);
                    if (fam != null) { how = "signing certificate"; break; }
                }
            }
            if (fam != null) {
                hits.add(a.pkg);
                findings.add(new Finding(Finding.Level.RED, "Spy apps",
                        "Known spy app found: " + a.label,
                        "\"" + a.label + "\" (" + a.pkg + ") matches the " + how + " of \""
                                + fam + "\", a known spy app or malware. This kind of app can secretly read messages, "
                                + "track location and record calls.\n\n"
                                + "Before removing it: if you think a specific person installed it, they may get an alert. "
                                + "Consider getting help first (India cyber helpline: 1930).")
                        .action("App info", Finding.ActionType.APP_INFO, a.pkg)
                        .action("Uninstall", Finding.ActionType.UNINSTALL, a.pkg)
                        .action("Call 1930", Finding.ActionType.DIAL, "1930"));
            }
        }
        if (hits.isEmpty()) {
            findings.add(new Finding(Finding.Level.GREEN, "Spy apps", "No known spy apps",
                    "Checked " + appsScanned + " apps against " + ioc.packages.size() + " package names and "
                            + ioc.certs.size() + " signing certificates from " + ioc.families.size()
                            + " spy-app and malware families, including government spyware such as Pegasus and Predator."));
        }
        return hits;
    }

    /** SHA-256 of each user-installed APK against known spy-app samples. Results cached until the app updates. */
    private void checkApkHashes(List<App> apps, Set<String> spyHits, Progress p) {
        SharedPreferences cache = ctx.getSharedPreferences("hash_cache", Context.MODE_PRIVATE);
        SharedPreferences.Editor ed = cache.edit();
        List<App> users = new ArrayList<>();
        for (App a : apps) if (!a.system && a.apk != null) users.add(a);
        int done = 0, matched = 0;
        for (App a : users) {
            done++;
            p.update("Checking app files (" + done + "/" + users.size() + "): " + a.label,
                    20 + (int) (60.0 * done / Math.max(1, users.size())));
            String hash = apkSha256Cached(a, cache, ed);
            if (hash == null) continue;
            String fam = ioc.hashes.get(hash);
            if (fam != null && !spyHits.contains(a.pkg)) {
                spyHits.add(a.pkg);
                matched++;
                findings.add(new Finding(Finding.Level.RED, "Spy apps",
                        "Known spy app file: " + a.label,
                        "The installed file of \"" + a.label + "\" (" + a.pkg + ") is identical to a known sample of \""
                                + fam + "\", a spy app or malware.")
                        .action("App info", Finding.ActionType.APP_INFO, a.pkg)
                        .action("Uninstall", Finding.ActionType.UNINSTALL, a.pkg));
            }
        }
        ed.apply();
        if (matched == 0 && !users.isEmpty()) {
            findings.add(new Finding(Finding.Level.GREEN, "Malware", "App files match no known spy-app samples",
                    "Fingerprinted " + users.size() + " installed apps and compared them with " + ioc.hashes.size()
                            + " known spy-app and malware files. For a wider malware check, use Tools → Malware database check."));
        }
    }

    static String apkSha256Cached(App a, SharedPreferences cache, SharedPreferences.Editor ed) {
        String cached = cache.getString(a.pkg, null);
        String stamp = a.updated + ":";
        if (cached != null && cached.startsWith(stamp)) return cached.substring(stamp.length());
        String h = fileSha256(a.apk);
        if (h != null) ed.putString(a.pkg, stamp + h);
        return h;
    }

    static String fileSha256(String path) {
        try {
            File f = new File(path);
            if (!f.canRead() || f.length() > 400L * 1024 * 1024) return null;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = new FileInputStream(f)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            }
            return Net.hex(md.digest());
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ hidden access

    private Set<String> enabledAccessibility() {
        Set<String> out = new HashSet<>();
        try {
            String s = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (s != null) {
                for (String part : s.split(":")) {
                    ComponentName cn = ComponentName.unflattenFromString(part.trim());
                    if (cn != null) out.add(cn.getPackageName());
                }
            }
        } catch (Exception ignored) { }
        return out;
    }

    private Set<String> activeAdmins() {
        Set<String> out = new HashSet<>();
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            List<ComponentName> list = dpm == null ? null : dpm.getActiveAdmins();
            if (list != null) for (ComponentName cn : list) out.add(cn.getPackageName());
        } catch (Exception ignored) { }
        return out;
    }

    private Set<String> enabledNotificationListeners() {
        try {
            String s = Settings.Secure.getString(cr, "enabled_notification_listeners");
            if (s == null) return null;
            Set<String> out = new HashSet<>();
            for (String part : s.split(":")) {
                ComponentName cn = ComponentName.unflattenFromString(part.trim());
                if (cn != null) out.add(cn.getPackageName());
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> servicesFor(String action) {
        Set<String> out = new HashSet<>();
        try {
            for (ResolveInfo ri : pm.queryIntentServices(new Intent(action), 0)) {
                if (ri.serviceInfo != null) out.add(ri.serviceInfo.packageName);
            }
        } catch (Exception ignored) { }
        return out;
    }

    private void checkHiddenAccess(List<App> apps, Map<String, App> byPkg, Set<String> spyHits,
                                   Set<String> accessibility, Set<String> admins,
                                   Set<String> notifEnabled, Set<String> notifCapable) {
        int issues = 0;

        for (String pkg : accessibility) {
            App a = byPkg.get(pkg);
            if (a == null || a.system || spyHits.contains(pkg) || trusted.contains(pkg)) continue;
            issues++;
            boolean bad = a.sideloaded || a.hidden;
            findings.add(new Finding(bad ? Finding.Level.RED : Finding.Level.YELLOW, "Hidden access",
                    "Can see and control your screen: " + a.label,
                    "\"" + a.label + "\" has Accessibility access. It can read everything on screen (messages, passwords, OTPs) "
                            + "and tap buttons for you. Spy apps almost always use this."
                            + (a.sideloaded ? "\n\n⚠ It was NOT installed from an app store." : "")
                            + (a.hidden ? "\n⚠ It has no icon in your app drawer." : "")
                            + "\n\nIf you didn't turn this on yourself, switch it off in Accessibility settings.")
                    .action("Accessibility settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_ACCESSIBILITY_SETTINGS)
                    .appActions(pkg));
        }

        for (String pkg : admins) {
            App a = byPkg.get(pkg);
            if (a == null || a.system || spyHits.contains(pkg) || trusted.contains(pkg)) continue;
            issues++;
            boolean bad = a.sideloaded || a.hidden;
            findings.add(new Finding(bad ? Finding.Level.RED : Finding.Level.YELLOW, "Hidden access",
                    "Device administrator: " + a.label,
                    "\"" + a.label + "\" is a device administrator. Admin apps can lock or wipe the phone and are hard to "
                            + "uninstall. Spy apps use this to stop you removing them. Work, school or anti-theft apps "
                            + "may legitimately use it."
                            + (a.sideloaded ? "\n\n⚠ It was NOT installed from an app store." : "")
                            + "\n\nTo remove it: Settings → Passwords & security → Privacy → Special app access → "
                            + "Device admin apps (wording differs by phone), switch it off, then uninstall.")
                    .action("Security settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_SECURITY_SETTINGS)
                    .appActions(pkg));
        }

        Set<String> notif = notifEnabled != null ? notifEnabled : new HashSet<>();
        for (String pkg : notif) {
            App a = byPkg.get(pkg);
            if (a == null || a.system || spyHits.contains(pkg) || trusted.contains(pkg)) continue;
            issues++;
            findings.add(new Finding(a.sideloaded || a.hidden ? Finding.Level.RED : Finding.Level.YELLOW,
                    "Hidden access", "Reads all your notifications: " + a.label,
                    "\"" + a.label + "\" can read every notification, including WhatsApp messages and bank OTPs. "
                            + "Smartwatch and fitness-band apps need this; most other apps don't."
                            + (a.sideloaded ? "\n\n⚠ It was NOT installed from an app store." : ""))
                    .action("Notification access", Finding.ActionType.OPEN_SETTINGS,
                            "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS")
                    .appActions(pkg));
        }
        if (notifEnabled == null) {
            StringBuilder sb = new StringBuilder();
            for (String pkg : notifCapable) {
                App a = byPkg.get(pkg);
                if (a != null && !a.system && !trusted.contains(pkg)) sb.append("• ").append(a.label).append('\n');
            }
            if (sb.length() > 0) {
                findings.add(new Finding(Finding.Level.INFO, "Hidden access",
                        "Apps that can ask to read notifications",
                        "This phone doesn't let apps see which of these are switched on, so check the list in "
                                + "Notification access settings:\n" + sb)
                        .action("Notification access", Finding.ActionType.OPEN_SETTINGS,
                                "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"));
            }
        }

        if (issues == 0) {
            findings.add(new Finding(Finding.Level.GREEN, "Hidden access", "No unusual hidden access",
                    "No downloaded app has Accessibility, device-admin or notification-reading access"
                            + (trusted.isEmpty() ? "." : " (apart from apps you marked as trusted).")));
        }
    }

    // ------------------------------------------------------------------ suspicion score

    /** AMDH-style score: combines install source, hidden icon, access and permissions. */
    private void checkSuspicionScore(List<App> apps, Set<String> spyHits, Set<String> accessibility,
                                     Set<String> admins, Set<String> notifEnabled, Set<String> cardEmulators) {
        for (App a : apps) {
            if (a.system || spyHits.contains(a.pkg) || trusted.contains(a.pkg)) continue;
            int score = 0;
            List<String> why = new ArrayList<>();
            if (a.sideloaded) {
                score += 3;
                why.add(a.installer == null ? "installed from outside an app store (USB/ADB or unknown)"
                        : "installed from a file, not an app store");
            }
            if (a.hidden) { score += 2; why.add("has no icon in the app drawer"); }
            if (accessibility.contains(a.pkg)) { score += 3; why.add("has Accessibility access"); }
            if (admins.contains(a.pkg)) { score += 3; why.add("is a device administrator"); }
            if (notifEnabled != null && notifEnabled.contains(a.pkg)) { score += 2; why.add("reads notifications"); }
            if (hasAny(a.granted, "android.permission.READ_SMS", "android.permission.RECEIVE_SMS")) {
                score += 2; why.add("can read your SMS");
            }
            if (a.granted.contains("android.permission.READ_CALL_LOG")) { score += 1; why.add("can read your call history"); }
            if (a.granted.contains("android.permission.RECORD_AUDIO")
                    && a.requested.contains("android.permission.RECEIVE_BOOT_COMPLETED")) {
                score += 1; why.add("can use the microphone and starts automatically at boot");
            }
            if (a.granted.contains("android.permission.ACCESS_BACKGROUND_LOCATION")) {
                score += 2; why.add("can track your location all the time");
            }
            if (a.requested.contains("android.permission.PACKAGE_USAGE_STATS")) {
                score += 1; why.add("asks to see which apps you use");
            }
            if (a.requested.contains("android.permission.REQUEST_INSTALL_PACKAGES") && !STORES.contains(a.pkg)) {
                score += 1; why.add("can install other apps");
            }
            // Banking trojans (2025-26 families such as Rokarolla, RemControl) put fake login screens over bank apps.
            if (a.sideloaded && canDrawOverApps(a)) {
                score += 2; why.add("can draw over other apps, which fake bank login screens need");
            }
            // NFC relay malware (NGate, SuperCard X) asks you to tap your bank card on the phone and relays it.
            if (a.sideloaded && a.requested.contains("android.permission.NFC")) {
                score += 1; why.add("can read contactless bank cards with NFC");
            }
            if (a.sideloaded && cardEmulators.contains(a.pkg)) {
                score += 2; why.add("can act as a contactless payment card");
            }
            if (a.sideloaded && looksLikeSystem(a.label)) {
                score += 2; why.add("downloaded app with a system-sounding name (\"" + a.label + "\")");
            }

            if (score >= 7 || (score >= 4 && a.sideloaded)) {
                Finding.Level lvl = score >= 7 ? Finding.Level.RED : Finding.Level.YELLOW;
                StringBuilder sb = new StringBuilder("\"" + a.label + "\" (" + a.pkg + ") looks suspicious because it:\n");
                for (String w : why) sb.append("• ").append(w).append('\n');
                sb.append("\nIf you installed it yourself and know what it is, tap \"I trust this app\".");
                findings.add(new Finding(lvl, "Suspicious apps", "Suspicious app: " + a.label, sb.toString())
                        .appActions(a.pkg));
            }
        }
    }

    /** True if the app may show windows over other apps ("Display over other apps"). */
    @SuppressWarnings("deprecation")
    private boolean canDrawOverApps(App a) {
        if (!a.requested.contains("android.permission.SYSTEM_ALERT_WINDOW")) return false;
        try {
            AppOpsManager ops = (AppOpsManager) ctx.getSystemService(Context.APP_OPS_SERVICE);
            int mode = Build.VERSION.SDK_INT >= 29
                    ? ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, a.uid, a.pkg)
                    : ops.checkOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, a.uid, a.pkg);
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ remote control

    /** Remote-support apps that let someone else see or control THIS phone. Used in screen-sharing UPI fraud. */
    static final Map<String, String> REMOTE_APPS = new HashMap<>();
    static {
        REMOTE_APPS.put("com.anydesk.anydeskandroid", "AnyDesk");
        REMOTE_APPS.put("com.teamviewer.quicksupport.market", "TeamViewer QuickSupport");
        REMOTE_APPS.put("com.teamviewer.host.market", "TeamViewer Host");
        REMOTE_APPS.put("com.carriez.flutter_hbb", "RustDesk");
        REMOTE_APPS.put("com.sand.airdroid", "AirDroid");
    }

    private Set<String> checkRemoteAccess(List<App> apps, Set<String> spyHits, Set<String> accessibility) {
        Set<String> hits = new HashSet<>();
        for (App a : apps) {
            if (a.system || spyHits.contains(a.pkg) || trusted.contains(a.pkg)) continue;
            String known = REMOTE_APPS.get(a.pkg);
            boolean control = accessibility.contains(a.pkg);
            // An unknown app that can both record the screen and tap for you works like a remote-control tool (SpyNote, Mirax).
            boolean screenAndControl = control
                    && a.requested.contains("android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION");
            if (known == null && !screenAndControl) continue;
            hits.add(a.pkg);
            String name = known != null ? known : a.label;
            Finding.Level lvl = control && (known != null || a.sideloaded) ? Finding.Level.RED : Finding.Level.YELLOW;
            String body = known != null
                    ? "\"" + a.label + "\" lets another person see your screen"
                            + (control ? " and control your phone. Its Accessibility access is ON, so they can control it right now." : ".")
                    : "\"" + a.label + "\" (" + a.pkg + ") can record your screen and has Accessibility access to tap and type "
                            + "for you. That is everything a remote-control tool needs."
                            + (a.sideloaded ? " It was installed from a file, not a store." : "");
            findings.add(new Finding(lvl, "Remote access", "Remote-control app: " + name,
                    body + "\n\nNo bank, UPI app, telecom company or government office will ever ask you to install AnyDesk, "
                            + "TeamViewer, RustDesk or any screen-sharing app. If a caller asked you to install this: uninstall it, "
                            + "change your UPI PIN and call 1930.\n\nIf you use it yourself (for example with your own computer), "
                            + "tap \"I trust this app\".")
                    .appActions(a.pkg)
                    .action("Call 1930", Finding.ActionType.DIAL, "1930"));
        }
        return hits;
    }

    private static boolean looksLikeSystem(String label) {
        String l = label.toLowerCase(Locale.ROOT);
        for (String w : SYSTEMY_WORDS) if (l.contains(w)) return true;
        return false;
    }

    private static boolean hasAny(Set<String> set, String... items) {
        for (String i : items) if (set.contains(i)) return true;
        return false;
    }

    // ------------------------------------------------------------------ sensitive permissions overview

    private void checkSensitivePermissions(List<App> apps, Set<String> spyHits) {
        TreeSet<String> bgLoc = new TreeSet<>(), mic = new TreeSet<>(), cam = new TreeSet<>(), sms = new TreeSet<>();
        for (App a : apps) {
            if (a.system || spyHits.contains(a.pkg)) continue;
            if (a.granted.contains("android.permission.ACCESS_BACKGROUND_LOCATION")) bgLoc.add(a.label);
            if (a.granted.contains("android.permission.RECORD_AUDIO")) mic.add(a.label);
            if (a.granted.contains("android.permission.CAMERA")) cam.add(a.label);
            if (hasAny(a.granted, "android.permission.READ_SMS", "android.permission.RECEIVE_SMS")) sms.add(a.label);
        }
        String privacy = Build.VERSION.SDK_INT >= 29 ? "android.settings.PRIVACY_SETTINGS" : Settings.ACTION_SETTINGS;
        if (!bgLoc.isEmpty()) {
            findings.add(new Finding(Finding.Level.YELLOW, "Permissions",
                    bgLoc.size() + " app(s) can see your location all the time",
                    "These downloaded apps are allowed to get your location even when you're not using them:\n"
                            + bullets(bgLoc) + "\nChange any you don't need to \"Only while using the app\".")
                    .action("Privacy settings", Finding.ActionType.OPEN_SETTINGS, privacy));
        }
        if (!sms.isEmpty()) {
            findings.add(new Finding(Finding.Level.INFO, "Permissions",
                    sms.size() + " app(s) can read your SMS (including OTPs)", bullets(sms))
                    .action("Privacy settings", Finding.ActionType.OPEN_SETTINGS, privacy));
        }
        if (!mic.isEmpty() || !cam.isEmpty()) {
            findings.add(new Finding(Finding.Level.INFO, "Permissions", "Apps allowed to use mic or camera",
                    (mic.isEmpty() ? "" : "Microphone (" + mic.size() + "):\n" + bullets(mic) + "\n")
                            + (cam.isEmpty() ? "" : "Camera (" + cam.size() + "):\n" + bullets(cam))
                            + "\nTip: the green dot at the top of the screen shows when the mic or camera is in use. "
                            + "Tap it to see which app.")
                    .action("Privacy settings", Finding.ActionType.OPEN_SETTINGS, privacy));
        }
    }

    private static String bullets(Set<String> items) {
        StringBuilder sb = new StringBuilder();
        for (String s : items) sb.append("• ").append(s).append('\n');
        return sb.toString();
    }

    // ------------------------------------------------------------------ interception

    private void checkInterception() {
        int issues = 0;

        // User-installed certificates let someone read your "secure" HTTPS traffic.
        List<String> userCerts = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!alias.startsWith("user:")) continue;
                String name = alias;
                try {
                    X509Certificate c = (X509Certificate) ks.getCertificate(alias);
                    name = c.getSubjectX500Principal().getName();
                } catch (Exception ignored) { }
                if (!trusted.contains("cert:" + alias)) userCerts.add(name);
            }
        } catch (Exception ignored) { }
        if (!userCerts.isEmpty()) {
            issues++;
            StringBuilder sb = new StringBuilder();
            for (String c : userCerts) sb.append("• ").append(c).append('\n');
            findings.add(new Finding(Finding.Level.RED, "Interception",
                    "Extra security certificate installed (" + userCerts.size() + ")",
                    "Someone (or an app) installed a certificate that can let them read your encrypted internet traffic, "
                            + "including passwords:\n" + sb
                            + "\nIf you didn't install it for work or school, remove it: Settings → Passwords & security → "
                            + "Privacy → Encryption & credentials → User credentials / Trusted credentials → User.")
                    .action("Security settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_SECURITY_SETTINGS));
        }

        // Proxy: traffic routed through someone else's server.
        String proxy = null;
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            ProxyInfo pi = cm == null ? null : cm.getDefaultProxy();
            if (pi != null && pi.getHost() != null && !pi.getHost().isEmpty()) proxy = pi.getHost() + ":" + pi.getPort();
        } catch (Exception ignored) { }
        if (proxy == null) {
            String h = System.getProperty("http.proxyHost");
            if (h != null && !h.isEmpty()) proxy = h + ":" + System.getProperty("http.proxyPort");
        }
        if (proxy != null) {
            issues++;
            findings.add(new Finding(Finding.Level.RED, "Interception", "Internet traffic goes through a proxy",
                    "Your connection is set to pass through " + proxy + ". If you didn't set this up, someone may be "
                            + "watching your traffic. Remove it in Wi-Fi settings → your network → Proxy → None.")
                    .action("Wi-Fi settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_WIFI_SETTINGS));
        }

        // VPN running right now.
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network n = cm == null ? null : cm.getActiveNetwork();
            NetworkCapabilities nc = n == null ? null : cm.getNetworkCapabilities(n);
            if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                issues++;
                findings.add(new Finding(Finding.Level.YELLOW, "Interception", "A VPN is active",
                        "All your internet traffic currently goes through a VPN. That's fine if it's one you chose "
                                + "(or a tracker blocker like TrackerControl). If you don't know which app it is, check VPN settings.")
                        .action("VPN settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_VPN_SETTINGS));
            }
        } catch (Exception ignored) { }

        if (issues == 0) {
            findings.add(new Finding(Finding.Level.GREEN, "Interception", "No signs of traffic interception",
                    "No extra security certificates, no proxy and no VPN."));
        }
    }

    // ------------------------------------------------------------------ device health

    private void checkDeviceHealth(Map<String, App> byPkg) {
        List<String> good = new ArrayList<>();

        KeyguardManager km = (KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
        if (km != null && !km.isDeviceSecure()) {
            findings.add(new Finding(Finding.Level.RED, "Phone security", "No screen lock",
                    "Anyone who picks up your phone can open it and install a spy app in under a minute. "
                            + "Set a PIN, password or pattern (a 6-digit PIN or longer is best).")
                    .action("Set screen lock", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_SECURITY_SETTINGS));
        } else {
            good.add("Screen lock is on");
        }

        String patch = Build.VERSION.SECURITY_PATCH;
        try {
            Date d = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).parse(patch);
            long months = (System.currentTimeMillis() - d.getTime()) / (30L * 24 * 3600 * 1000);
            if (months > 12) {
                findings.add(new Finding(Finding.Level.RED, "Phone security", "Security updates are very old",
                        "Last security patch: " + patch + " (" + months + " months ago). Known hacks may work on this phone. "
                                + "Check Settings → About phone → System update. If your phone no longer gets updates, "
                                + "be extra careful with links and downloads.")
                        .action("System settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_DEVICE_INFO_SETTINGS));
            } else if (months > 4) {
                findings.add(new Finding(Finding.Level.YELLOW, "Phone security", "Security update is a few months old",
                        "Last security patch: " + patch + " (" + months + " months ago). Check for a system update.")
                        .action("System settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_DEVICE_INFO_SETTINGS));
            } else {
                good.add("Security patch is recent (" + patch + ")");
            }
        } catch (Exception ignored) { }

        try {
            DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            int enc = dpm.getStorageEncryptionStatus();
            if (enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                    || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER) {
                good.add("Storage is encrypted");
            } else if (enc == DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE
                    || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY) {
                findings.add(new Finding(Finding.Level.YELLOW, "Phone security", "Storage encryption is weak",
                        "Your data is not protected by your screen lock. Setting a PIN usually fixes this."));
            }
        } catch (Exception ignored) { }

        int dev = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
        int adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0);
        int adbWifi = Settings.Global.getInt(cr, "adb_wifi_enabled", 0);
        if (adbWifi == 1) {
            findings.add(new Finding(Finding.Level.RED, "Phone security", "Wireless debugging is ON",
                    "Wireless debugging lets a computer on the same Wi-Fi control this phone. Turn it off unless "
                            + "you're using it right now.")
                    .action("Developer options", Finding.ActionType.OPEN_SETTINGS,
                            Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));
        } else if (adb == 1) {
            findings.add(new Finding(Finding.Level.YELLOW, "Phone security", "USB debugging is ON",
                    "With USB debugging on, someone with your unlocked phone and a computer can install apps silently. "
                            + "Turn it off unless you're using it right now.")
                    .action("Developer options", Finding.ActionType.OPEN_SETTINGS,
                            Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));
        } else if (dev == 1) {
            findings.add(new Finding(Finding.Level.INFO, "Phone security", "Developer options are enabled",
                    "Not dangerous by itself, but you can switch Developer options off if you don't use them."));
        } else {
            good.add("USB and wireless debugging are off");
        }

        List<String> root = new ArrayList<>();
        for (String path : new String[]{"/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk"}) {
            if (new File(path).exists()) root.add(path);
        }
        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) root.add("test-keys build");
        for (String p : new String[]{"com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu"}) {
            if (byPkg.containsKey(p)) root.add(p);
        }
        if (!root.isEmpty()) {
            findings.add(new Finding(Finding.Level.YELLOW, "Phone security", "Phone appears to be rooted",
                    "Signs of root access: " + String.join(", ", root) + ". Rooting removes Android's main protections. "
                            + "If you didn't root it yourself, someone else may have."));
        } else {
            good.add("No signs of rooting");
        }

        checkBootState(good);
        checkAdvancedProtection(good);

        if (Build.VERSION.SDK_INT < 29) {
            findings.add(new Finding(Finding.Level.YELLOW, "Phone security", "Old Android version",
                    "Android " + Build.VERSION.RELEASE + " lacks many newer privacy protections."));
        }

        if (!good.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (String g : good) sb.append("✓ ").append(g).append('\n');
            findings.add(new Finding(Finding.Level.GREEN, "Phone security", "Security basics", sb.toString().trim()));
        }
    }

    /** Bootloader lock state as reported by the phone's security chip (key attestation). */
    private void checkBootState(List<String> good) {
        Attestation.Result r = Attestation.check();
        if (r == null) return; // this phone has no hardware attestation; the file-based root check above still ran
        if (!r.trustedRoot) {
            findings.add(new Finding(Finding.Level.INFO, "Phone security", "Couldn't confirm the hardware security check",
                    "The phone's security chip answered, but its certificate doesn't lead back to Google's key. "
                            + "Some phones made without Google services do this. On a normal Android phone it can mean "
                            + "the system was modified."));
        } else if (!r.deviceLocked) {
            findings.add(new Finding(Finding.Level.YELLOW, "Phone security", "Bootloader is unlocked",
                    "The phone's security chip reports an unlocked bootloader. That lets anyone with the phone install "
                            + "a modified Android that can hide spy software from every app, including this one. "
                            + "If you didn't unlock it yourself, take the phone to an authorised service centre."));
        } else if (r.verifiedBootState == Attestation.SELF_SIGNED) {
            findings.add(new Finding(Finding.Level.INFO, "Phone security", "Custom operating system",
                    "The bootloader is locked, but the phone runs an operating system not signed by its maker "
                            + "(for example GrapheneOS or CalyxOS). That's fine if you installed it yourself."));
        } else if (r.verifiedBootState == Attestation.VERIFIED) {
            good.add("Bootloader is locked and Android is verified (hardware check)");
        } else {
            findings.add(new Finding(Finding.Level.YELLOW, "Phone security", "Android failed its startup check",
                    "The phone's security chip says the system didn't pass Verified Boot. The software may have been "
                            + "modified. Take the phone to an authorised service centre."));
        }
    }

    /** Android 16+ Advanced Protection: Google's strongest settings for people at risk of targeted attacks. */
    private void checkAdvancedProtection(List<String> good) {
        if (Build.VERSION.SDK_INT < 36) return;
        try {
            // Reflection, so the app still builds against an older SDK.
            Class<?> c = Class.forName("android.security.advancedprotection.AdvancedProtectionManager");
            Object m = ctx.getSystemService(c);
            if (m == null) return;
            boolean on = (Boolean) c.getMethod("isAdvancedProtectionEnabled").invoke(m);
            if (on) {
                good.add("Advanced Protection is on");
            } else {
                findings.add(new Finding(Finding.Level.INFO, "Phone security", "Advanced Protection is available",
                        "This phone has Android's Advanced Protection: the strongest settings, meant for people at risk "
                                + "of targeted attacks (journalists, activists, anyone being stalked). It blocks app "
                                + "installs from outside the Play Store and turns on extra theft and scam protection. "
                                + "Settings → Security & privacy → Advanced Protection.")
                        .action("Security settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_SECURITY_SETTINGS));
            }
        } catch (Throwable ignored) { }
    }

    // ------------------------------------------------------------------ last used

    /**
     * Adds when each flagged app was last opened or ran in the background, if the user allowed
     * Usage access. Otherwise adds one finding explaining how to turn it on.
     */
    private void addLastUsed() {
        Map<String, UsageStats> usage = usageStats();
        boolean anyApp = false;
        for (Finding f : findings) {
            String pkg = null;
            for (Finding.Action a : f.actions) if (a.type == Finding.ActionType.APP_INFO) { pkg = a.target; break; }
            if (pkg == null) continue;
            anyApp = true;
            if (usage == null) continue;
            UsageStats u = usage.get(pkg);
            String opened = u == null || u.getLastTimeUsed() <= 0 ? "not in the last 30 days" : ago(u.getLastTimeUsed());
            String bg = "";
            if (Build.VERSION.SDK_INT >= 29) {
                long t = u == null ? 0 : u.getLastTimeForegroundServiceUsed();
                bg = "\nLast ran in the background: " + (t <= 0 ? "not in the last 30 days" : ago(t));
            }
            f.detail = f.detail + "\n\nLast opened: " + opened + bg;
        }
        if (anyApp && usage == null) {
            findings.add(new Finding(Finding.Level.INFO, "Permissions", "See when flagged apps last ran",
                    "Allow Aegis \"Usage access\" and scan again to see when each app above was last opened or ran in "
                            + "the background. Aegis only reads this on the phone.")
                    .action("Usage access", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_USAGE_ACCESS_SETTINGS));
        }
    }

    /** Last 30 days of app usage, or null if the user hasn't allowed Usage access. */
    @SuppressWarnings("deprecation")
    private Map<String, UsageStats> usageStats() {
        try {
            AppOpsManager ops = (AppOpsManager) ctx.getSystemService(Context.APP_OPS_SERVICE);
            int mode = Build.VERSION.SDK_INT >= 29
                    ? ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), ctx.getPackageName())
                    : ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), ctx.getPackageName());
            if (mode != AppOpsManager.MODE_ALLOWED) return null;
            UsageStatsManager usm = (UsageStatsManager) ctx.getSystemService(Context.USAGE_STATS_SERVICE);
            long now = System.currentTimeMillis();
            return usm.queryAndAggregateUsageStats(now - 30L * 24 * 3600 * 1000, now);
        } catch (Exception e) {
            return null;
        }
    }

    private static String ago(long t) {
        return DateUtils.getRelativeTimeSpanString(t, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString();
    }

    // ------------------------------------------------------------------ snapshot

    /** Saves this scan and reports anything new since the previous one. */
    private void checkSnapshot(List<App> apps, Set<String> accessibility, Set<String> admins) {
        Set<String> nowApps = new HashSet<>();
        Map<String, String> labels = new HashMap<>();
        for (App a : apps) {
            if (!a.system) { nowApps.add(a.pkg); labels.put(a.pkg, a.label); }
        }
        Set<String> oldApps = prefs.getStringSet("snap_apps", null);
        Set<String> oldAcc = prefs.getStringSet("snap_access", new HashSet<>());
        Set<String> oldAdm = prefs.getStringSet("snap_admins", new HashSet<>());
        long lastTime = prefs.getLong("snap_time", 0);

        if (oldApps == null) {
            findings.add(new Finding(Finding.Level.INFO, "Changes", "First scan saved as your baseline",
                    "Next time you scan, Aegis will show any app or access that appeared since today. "
                            + "Scan again after your phone has been out of your hands (repair shop, borrowed, etc.)."));
        } else {
            TreeSet<String> newApps = new TreeSet<>();
            for (String p : nowApps) if (!oldApps.contains(p)) newApps.add(labels.get(p) + " (" + p + ")");
            TreeSet<String> newAccess = new TreeSet<>();
            for (String p : accessibility) if (!oldAcc.contains(p)) newAccess.add("Accessibility: " + p);
            for (String p : admins) if (!oldAdm.contains(p)) newAccess.add("Device admin: " + p);
            String since = new SimpleDateFormat("d MMM yyyy, h:mm a", Locale.getDefault()).format(new Date(lastTime));
            if (newApps.isEmpty() && newAccess.isEmpty()) {
                findings.add(new Finding(Finding.Level.GREEN, "Changes", "Nothing new since your last scan",
                        "No new apps or access since " + since + "."));
            } else {
                StringBuilder sb = new StringBuilder("Since " + since + ":\n");
                for (String s : newAccess) sb.append("• ").append(s).append('\n');
                for (String s : newApps) sb.append("• New app: ").append(s).append('\n');
                sb.append("\nIf you didn't install these yourself, look at them carefully.");
                findings.add(new Finding(newAccess.isEmpty() ? Finding.Level.INFO : Finding.Level.YELLOW,
                        "Changes", "New since your last scan", sb.toString()));
            }
        }
        prefs.edit()
                .putStringSet("snap_apps", nowApps)
                .putStringSet("snap_access", new HashSet<>(accessibility))
                .putStringSet("snap_admins", new HashSet<>(admins))
                .putLong("snap_time", System.currentTimeMillis())
                .apply();
    }

    // ------------------------------------------------------------------ helpers

    static String sha1(byte[] data) {
        try {
            return Net.hex(MessageDigest.getInstance("SHA-1").digest(data)).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    static String sha256(byte[] data) {
        try {
            return Net.hex(MessageDigest.getInstance("SHA-256").digest(data)).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    /** Non-system apps with their APK paths, for the Tools tab. */
    static List<App> userApps(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        List<App> out = new ArrayList<>();
        for (PackageInfo pi : pm.getInstalledPackages(0)) {
            ApplicationInfo ai = pi.applicationInfo;
            if (ai == null || (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
            if (pi.packageName.equals(ctx.getPackageName())) continue;
            App a = new App();
            a.pkg = pi.packageName;
            a.apk = ai.sourceDir;
            a.updated = pi.lastUpdateTime;
            try { a.label = pm.getApplicationLabel(ai).toString(); } catch (Exception e) { a.label = a.pkg; }
            out.add(a);
        }
        Collections.sort(out, (x, y) -> x.label.compareToIgnoreCase(y.label));
        return out;
    }
}
