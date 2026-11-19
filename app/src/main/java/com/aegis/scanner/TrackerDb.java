package com.aegis.scanner;

import android.content.Context;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Finds tracking libraries inside apps, the same way Exodus Privacy does:
 * list the Java classes inside each app's code (classes*.dex) and match them
 * against known tracker code signatures (package names).
 *
 * "Contains a tracker" means the code is inside the app; it does not prove
 * the tracker is active.
 */
public class TrackerDb {

    /**
     * Exodus Privacy's tracker list (ODbL 1.0), as mirrored by AndroDR's rules project.
     * Exodus asks end-user apps not to call its API, so the app ships a copy and updates from the mirror.
     */
    public static final String TRACKERS_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/trackers.yml";
    public static final String FILE_NAME = "trackers.yml";

    /** Path prefix like "com/appsflyer/" -> tracker name */
    private final Map<String, String> prefixes = new HashMap<>();
    /** Signatures that are not whole packages, checked with startsWith */
    private final List<String[]> partial = new ArrayList<>();
    public boolean fromExodus = false;

    /** Small fallback list, used only if the bundled Exodus list can't be read. */
    private static final String[][] BUILT_IN = {
            {"Google Firebase Analytics", "com.google.firebase.analytics.|com.google.android.gms.measurement."},
            {"Google Analytics", "com.google.android.gms.analytics.|com.google.analytics."},
            {"Google AdMob", "com.google.android.gms.ads."},
            {"Google Tag Manager", "com.google.android.gms.tagmanager.|com.google.tagmanager."},
            {"Google Crashlytics", "com.crashlytics.|com.google.firebase.crashlytics."},
            {"Facebook Analytics", "com.facebook.appevents.|com.facebook.marketing."},
            {"Facebook Ads", "com.facebook.ads."},
            {"Facebook Login", "com.facebook.login."},
            {"AppsFlyer", "com.appsflyer."},
            {"Adjust", "com.adjust.sdk."},
            {"Branch", "io.branch."},
            {"Mixpanel", "com.mixpanel."},
            {"Amplitude", "com.amplitude."},
            {"CleverTap", "com.clevertap."},
            {"MoEngage", "com.moengage."},
            {"WebEngage", "com.webengage."},
            {"OneSignal", "com.onesignal."},
            {"Flurry", "com.flurry."},
            {"Segment", "com.segment.analytics."},
            {"Braze", "com.braze.|com.appboy."},
            {"Kochava", "com.kochava."},
            {"Singular", "com.singular.sdk."},
            {"Unity Ads", "com.unity3d.ads.|com.unity3d.services."},
            {"AppLovin", "com.applovin."},
            {"ironSource", "com.ironsource."},
            {"InMobi", "com.inmobi."},
            {"Chartboost", "com.chartboost."},
            {"Vungle / Liftoff", "com.vungle."},
            {"Mintegral", "com.mbridge.msdk."},
            {"Pangle (ByteDance)", "com.bytedance.sdk.openadsdk."},
            {"Huawei Analytics", "com.huawei.hms.analytics."},
            {"Yandex AppMetrica", "com.yandex.metrica.|io.appmetrica."},
            {"Microsoft App Center", "com.microsoft.appcenter.analytics."},
            {"Sentry", "io.sentry."},
            {"New Relic", "com.newrelic.agent."},
            {"Instabug", "com.instabug."},
            {"Smartlook", "com.smartlook."},
            {"Tencent Bugly", "com.tencent.bugly."},
            {"Umeng", "com.umeng."},
    };

    public static TrackerDb load(Context ctx) {
        TrackerDb db = new TrackerDb();
        try (InputStream in = IocDb.open(ctx, FILE_NAME)) {
            db.loadTrackersYaml(in);
            db.fromExodus = db.prefixes.size() > 50;
        } catch (Exception ignored) { }
        if (!db.fromExodus) {
            db.prefixes.clear();
            db.partial.clear();
            for (String[] t : BUILT_IN) db.addSignature(t[0], t[1]);
        }
        return db;
    }

    public int size() {
        return prefixes.size() + partial.size();
    }

    /**
     * Reads trackers.yml: "- id: N" entries with "  name: X" and a "  code_prefixes:" list
     * of Java package names ("  - com.appsflyer").
     */
    public void loadTrackersYaml(InputStream in) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line, name = null, key = null;
        while ((line = r.readLine()) != null) {
            if (line.startsWith("- id:")) { name = null; key = null; continue; }
            String t = line.trim();
            if (line.startsWith("  ") && !t.startsWith("- ") && t.contains(":")) {
                key = t.substring(0, t.indexOf(':'));
                if (key.equals("name")) name = unquote(t.substring(5).trim());
                continue;
            }
            if (t.startsWith("- ") && "code_prefixes".equals(key) && name != null) {
                String prefix = unquote(t.substring(2).trim());
                if (!prefix.isEmpty()) addSignature(name, prefix.endsWith(".") ? prefix : prefix + ".");
            }
        }
    }

    private static String unquote(String s) {
        if (s.length() >= 2 && (s.charAt(0) == '"' || s.charAt(0) == '\'') && s.charAt(s.length() - 1) == s.charAt(0)) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    private void addSignature(String name, String signature) {
        for (String alt : signature.split("\\|")) {
            String s = alt.trim().replace("\\", "").replace("^", "").replace("$", "");
            if (s.length() < 4) continue;
            String path = s.replace('.', '/');
            if (path.endsWith("/")) prefixes.put(path, name);
            else partial.add(new String[]{path, name});
        }
    }

    /** Scans one APK file and returns the tracker names found in it. */
    public TreeSet<String> scanApk(String apkPath) {
        TreeSet<String> found = new TreeSet<>();
        try (ZipFile zip = new ZipFile(apkPath)) {
            Enumeration<? extends ZipEntry> en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String n = e.getName();
                if (!n.startsWith("classes") || !n.endsWith(".dex") || n.contains("/")) continue;
                long size = e.getSize();
                if (size <= 0x70 || size > 64L * 1024 * 1024) continue;
                byte[] dex = new byte[(int) size];
                try (DataInputStream in = new DataInputStream(zip.getInputStream(e))) {
                    in.readFully(dex);
                }
                matchDex(dex, found);
            }
        } catch (Throwable ignored) {
            // Unreadable or unusual APK: report nothing rather than crash.
        }
        return found;
    }

    /** Reads class names from a DEX file's string table and matches them. */
    private void matchDex(byte[] dex, TreeSet<String> found) {
        int count = readInt(dex, 0x38);
        int idsOff = readInt(dex, 0x3C);
        if (count <= 0 || idsOff <= 0 || idsOff + (long) count * 4 > dex.length) return;
        for (int i = 0; i < count; i++) {
            int off = readInt(dex, idsOff + i * 4);
            if (off <= 0 || off >= dex.length) continue;
            // skip the uleb128 length prefix
            int p = off;
            while (p < dex.length && (dex[p] & 0x80) != 0) p++;
            p++;
            if (p >= dex.length || dex[p] != 'L') continue;
            int end = p;
            while (end < dex.length && dex[end] != 0 && dex[end] != ';') end++;
            if (end >= dex.length || dex[end] != ';') continue;
            String cls = new String(dex, p + 1, end - p - 1, StandardCharsets.ISO_8859_1);
            matchClass(cls, found);
        }
    }

    private void matchClass(String cls, TreeSet<String> found) {
        int idx = cls.indexOf('/');
        while (idx > 0) {
            String hit = prefixes.get(cls.substring(0, idx + 1));
            if (hit != null) found.add(hit);
            idx = cls.indexOf('/', idx + 1);
        }
        for (String[] p : partial) {
            if (cls.startsWith(p[0])) found.add(p[1]);
        }
    }

    private static int readInt(byte[] b, int off) {
        if (off < 0 || off + 4 > b.length) return -1;
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toString("UTF-8");
    }
}
