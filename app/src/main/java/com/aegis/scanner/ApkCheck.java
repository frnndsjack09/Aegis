package com.aegis.scanner;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Checks an app file (.apk) BEFORE it is installed: the "Wedding_Invite.apk" / "RTO_Challan.apk" /
 * "SBI Rewards.apk" files sent over WhatsApp that install banking malware. Reads the file without
 * installing or running it. {@link #judge} is pure Java so it can be unit-tested.
 */
public final class ApkCheck {

    /** Everything read from the file. Filled by {@link #inspect}, or by hand in tests. */
    public static final class Facts {
        public String fileName = "", label = "", pkg = "", version = "";
        public boolean parsed;
        public final Set<String> perms = new HashSet<>();
        public boolean accessibilityService, notificationListener, deviceAdmin, cardEmulator;
        public String sha256 = "";
        public final List<String> certs = new ArrayList<>();
        /** Known malware family and what matched, or null. */
        public String iocFamily, iocHow;
        /** Label of the installed app with the same package name, or null if not installed. */
        public String installedLabel;
        /** True if the installed app with the same package name is signed by someone else. */
        public boolean signerDiffers;
        /** True if it's signed by the same developer as the installed app: a genuine update. */
        public boolean sameSigner;
    }

    public static final class Verdict {
        public Finding.Level level;
        public String headline;
        public final List<String> reasons = new ArrayList<>();
        public int score;
    }

    // Lures seen in India in 2025-26: wedding invites, RTO e-challans, reward points, KYC, govt schemes.
    private static final Pattern LURE = Pattern.compile(
            "wedding|invit|shaadi|shadi|vivah|nimantran|challan|\\brto\\b|parivahan|traffic|kyc|reward|points|bonus|"
                    + "kisan|aadhaa?r|aadhar|pan.?card|bijli|electric|refund|income.?tax|customer.?care|courier|"
                    + "delivery|parcel|photo|video|document|pdf|invoice|bill",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern BANK = Pattern.compile(
            "\\bsbi\\b|yono|hdfc|icici|axis|kotak|\\bpnb\\b|canara|baroda|bank|paytm|phone ?pe|gpay|google ?pay|"
                    + "\\bbhim\\b|\\bupi\\b|credit ?card",
            Pattern.CASE_INSENSITIVE);

    public static Verdict judge(Facts f) {
        Verdict v = new Verdict();
        if (!f.parsed) {
            v.level = Finding.Level.YELLOW;
            v.headline = "This isn't a normal app file";
            v.reasons.add("Android can't read it as an app. It may be damaged, a split bundle (.apks/.xapk) "
                    + "or something pretending to be an app. Don't install it from where you got it.");
            return v;
        }
        if (f.iocFamily != null) {
            v.level = Finding.Level.RED;
            v.headline = "Known malware: " + f.iocFamily;
            v.reasons.add("Its " + f.iocHow + " matches \"" + f.iocFamily + "\", a known spy app or malware.");
            return v;
        }
        if (f.signerDiffers) {
            v.level = Finding.Level.RED;
            v.headline = "Fake copy of " + f.installedLabel;
            v.reasons.add("It uses the same app id as \"" + f.installedLabel + "\" on your phone but was signed by "
                    + "someone else. Real updates are always signed by the same developer.");
            return v;
        }
        // A file is never "from a store", so any bank-named file that isn't the official app id counts.
        String fake = BankApps.fakeReason(f.label, f.pkg, false);
        if (fake != null && !f.sameSigner) {
            v.level = Finding.Level.RED;
            v.headline = "Fake bank app";
            v.reasons.add(fake);
            return v;
        }
        if (f.sameSigner) {
            v.level = Finding.Level.GREEN;
            v.headline = "Genuine copy of " + f.installedLabel;
            v.reasons.add("It's signed by the same developer as \"" + f.installedLabel + "\" already on your phone. "
                    + "Nobody else can sign with that key. The file name doesn't matter.");
            return v;
        }
        // Underscores and dots join words in file names ("Wedding_Invite.apk"); make them spaces so \b works.
        String name = (f.fileName + " " + f.label).replaceAll("[_.\\-]+", " ");
        int s = 0;
        if (LURE.matcher(name).find()) {
            s += 3;
            v.reasons.add("Its name (\"" + (f.fileName.isEmpty() ? f.label : f.fileName) + "\") looks like a "
                    + "document, invitation, challan or reward. Real invitations, bills and challans are never apps.");
        }
        if (BANK.matcher(name).find()) {
            s += 3;
            v.reasons.add("It uses a bank or payment app name. Real bank and UPI apps come only from the Play Store.");
        }
        if (f.perms.contains("android.permission.READ_SMS") || f.perms.contains("android.permission.RECEIVE_SMS")) {
            s += 3; v.reasons.add("It wants to read your SMS, which includes bank OTPs.");
        }
        if (f.perms.contains("android.permission.SEND_SMS")) {
            s += 1; v.reasons.add("It can send SMS from your number.");
        }
        if (f.accessibilityService) {
            s += 3; v.reasons.add("It asks for Accessibility access, which lets it see your screen and tap for you.");
        }
        if (f.notificationListener) {
            s += 2; v.reasons.add("It can read all your notifications, including OTPs.");
        }
        if (f.deviceAdmin) {
            s += 2; v.reasons.add("It asks to become a device administrator, which makes it hard to uninstall.");
        }
        if (f.perms.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
            s += 1; v.reasons.add("It can draw over other apps, for example a fake bank login screen.");
        }
        if (f.cardEmulator) {
            s += 2; v.reasons.add("It can act as a contactless payment card.");
        } else if (f.perms.contains("android.permission.NFC")) {
            s += 1; v.reasons.add("It can read contactless bank cards with NFC.");
        }
        if (f.perms.contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
            s += 1; v.reasons.add("It can install more apps.");
        }
        if (f.perms.contains("android.permission.READ_CALL_LOG")) {
            s += 1; v.reasons.add("It can read your call history.");
        }
        if (f.perms.contains("android.permission.READ_CONTACTS")) {
            s += 1; v.reasons.add("It can read your contacts.");
        }
        v.score = s;
        if (s >= 5) {
            v.level = Finding.Level.RED;
            v.headline = "Don't install this app";
        } else if (s >= 2) {
            v.level = Finding.Level.YELLOW;
            v.headline = "Be careful with this app";
        } else {
            v.level = Finding.Level.GREEN;
            v.headline = "No warning signs found";
        }
        return v;
    }

    /** Copies the file to private storage, reads it without installing, then deletes the copy. */
    @SuppressWarnings("deprecation")
    public static Facts inspect(Context ctx, Uri uri, IocDb ioc) throws Exception {
        Facts f = new Facts();
        f.fileName = displayName(ctx, uri);
        File tmp = new File(ctx.getCacheDir(), "inspect.apk");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long total = 0;
            try (InputStream in = ctx.getContentResolver().openInputStream(uri);
                 OutputStream out = new FileOutputStream(tmp)) {
                if (in == null) throw new Exception("Couldn't open the file");
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > 400L * 1024 * 1024) throw new Exception("File is larger than 400 MB");
                    md.update(buf, 0, n);
                    out.write(buf, 0, n);
                }
            }
            f.sha256 = Net.hex(md.digest()).toLowerCase(Locale.ROOT);

            PackageManager pm = ctx.getPackageManager();
            int sig = Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
            PackageInfo pi = pm.getPackageArchiveInfo(tmp.getPath(),
                    PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS | sig);
            if (pi == null || pi.applicationInfo == null) {
                String fam = ioc.hashes.get(f.sha256);
                if (fam != null) { f.parsed = true; f.iocFamily = fam; f.iocHow = "file fingerprint"; }
                return f;
            }
            f.parsed = true;
            f.pkg = pi.packageName;
            f.version = pi.versionName == null ? "" : pi.versionName;
            ApplicationInfo ai = pi.applicationInfo;
            ai.sourceDir = tmp.getPath();
            ai.publicSourceDir = tmp.getPath();
            try { f.label = pm.getApplicationLabel(ai).toString(); } catch (Exception e) { f.label = f.pkg; }
            fill(f, pi);
            String fam = ioc.hashes.get(f.sha256);
            if (fam != null) { f.iocFamily = fam; f.iocHow = "file fingerprint"; }
            matchIoc(f, ioc, pm);

            try {
                PackageInfo inst = pm.getPackageInfo(f.pkg, sig);
                f.installedLabel = pm.getApplicationLabel(inst.applicationInfo).toString();
                Set<String> mine = new HashSet<>();
                for (Signature s : signatures(inst)) mine.add(Scanner.sha256(s.toByteArray()));
                boolean overlap = false;
                for (String c : f.certs) if (mine.contains(c)) overlap = true;
                f.signerDiffers = !mine.isEmpty() && !f.certs.isEmpty() && !overlap;
                f.sameSigner = overlap;
            } catch (PackageManager.NameNotFoundException notInstalled) {
                f.installedLabel = null;
            }
            return f;
        } finally {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
        }
    }

    /** Permissions, sensitive services and signing certificates from a parsed app (file or installed). */
    static void fill(Facts f, PackageInfo pi) {
        if (pi.requestedPermissions != null) for (String p : pi.requestedPermissions) f.perms.add(p);
        if (pi.services != null) for (ServiceInfo s : pi.services) {
            if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(s.permission)) f.accessibilityService = true;
            if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".equals(s.permission)) f.notificationListener = true;
            if ("android.permission.BIND_NFC_SERVICE".equals(s.permission)) f.cardEmulator = true;
        }
        if (pi.receivers != null) for (ActivityInfo r : pi.receivers) {
            if ("android.permission.BIND_DEVICE_ADMIN".equals(r.permission)) f.deviceAdmin = true;
        }
        for (Signature s : signatures(pi)) {
            f.certs.add(Scanner.sha1(s.toByteArray()));
            f.certs.add(Scanner.sha256(s.toByteArray()));
        }
    }

    /** Known malware by app id, then certificate (skipping certs that also sign this phone's system apps). */
    static void matchIoc(Facts f, IocDb ioc, PackageManager pm) {
        String fam;
        if (f.iocFamily == null && (fam = ioc.packages.get(f.pkg)) != null) { f.iocFamily = fam; f.iocHow = "app id (" + f.pkg + ")"; }
        if (f.iocFamily != null) return;
        Set<String> systemCerts = systemCerts(pm);
        for (String c : f.certs) {
            if (systemCerts.contains(c)) continue;
            if ((fam = ioc.certs.get(c)) != null) { f.iocFamily = fam; f.iocHow = "signing certificate"; return; }
        }
    }

    static int sigFlag() {
        return Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
    }

    private static String displayName(Context ctx, Uri uri) {
        try (Cursor c = ctx.getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getString(0);
        } catch (Exception ignored) { }
        String last = uri.getLastPathSegment();
        return last == null ? "" : last;
    }

    @SuppressWarnings("deprecation")
    private static Signature[] signatures(PackageInfo pi) {
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

    private static Set<String> systemCertCache;

    /** Certificates that sign this phone's system apps. Cached: system apps only change with an OS update. */
    private static synchronized Set<String> systemCerts(PackageManager pm) {
        if (systemCertCache != null) return systemCertCache;
        Set<String> out = new HashSet<>();
        try {
            for (PackageInfo p : pm.getInstalledPackages(sigFlag())) {
                if (p.applicationInfo == null || (p.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) continue;
                for (Signature s : signatures(p)) {
                    out.add(Scanner.sha1(s.toByteArray()));
                    out.add(Scanner.sha256(s.toByteArray()));
                }
            }
        } catch (Exception ignored) { }
        systemCertCache = out;
        return out;
    }
}
