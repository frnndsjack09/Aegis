package com.aegis.scanner;

import android.content.pm.PackageManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import rikka.shizuku.Shizuku;

/**
 * Optional deep check through Shizuku (a free app that gives other apps the same access as a
 * USB-connected computer, without root). With it, Aegis can read Android's own record of when
 * each app last used the microphone, camera, location, SMS or clipboard: something normal apps
 * can't see. Read-only: Aegis only runs "appops get".
 */
public final class ShizukuOps {

    public static final int REQUEST_CODE = 4711;

    /** App-op name -> what people call it. */
    private static final Map<String, String> OPS = new HashMap<>();
    static {
        OPS.put("RECORD_AUDIO", "Microphone");
        OPS.put("CAMERA", "Camera");
        OPS.put("FINE_LOCATION", "Location");
        OPS.put("COARSE_LOCATION", "Location");
        OPS.put("READ_SMS", "SMS");
        OPS.put("READ_CLIPBOARD", "Clipboard");
        OPS.put("READ_CALL_LOG", "Call history");
        OPS.put("READ_CONTACTS", "Contacts");
    }

    /** Op header, e.g. "RECORD_AUDIO: allow". */
    private static final Pattern OP = Pattern.compile("^\\s*([A-Z_]+):\\s");
    /** Android 10 and older: "RECORD_AUDIO: allow; time=+1h2m3s456ms ago; duration=+5s". */
    private static final Pattern OLD_TIME = Pattern.compile("time=\\+([0-9dhms]+?)(?:\\d+ms)? ago");
    /** Android 11+: "Access: [fg-s] 2026-11-19 10:00:00.000 (-2h3m4s5ms) duration=+5s" under the op. */
    private static final Pattern NEW_TIME = Pattern.compile("Access:.*\\(-([0-9dhms]+?)(?:\\d+ms)?\\)");
    private static final Pattern SAFE_PKG = Pattern.compile("[A-Za-z0-9._]+");

    public static final class Use {
        public String pkg, label, what, ago;
        public long agoMs;
    }

    public static boolean running() {
        try { return Shizuku.pingBinder(); } catch (Throwable t) { return false; }
    }

    public static boolean granted() {
        try {
            return !Shizuku.isPreV11() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            return false;
        }
    }

    public static void request() {
        try { Shizuku.requestPermission(REQUEST_CODE); } catch (Throwable ignored) { }
    }

    /** Last use of sensitive features by each app, most recent first. */
    public static List<Use> recentUses(List<Scanner.App> apps) throws Exception {
        StringBuilder script = new StringBuilder();
        Map<String, String> labels = new HashMap<>();
        for (Scanner.App a : apps) {
            if (!SAFE_PKG.matcher(a.pkg).matches()) continue; // package names go into a shell command
            labels.put(a.pkg, a.label);
            script.append("echo '##").append(a.pkg).append("'; appops get ").append(a.pkg).append("; ");
        }
        Process p = newProcess(new String[]{"sh", "-c", script.toString()});
        List<Use> out = new ArrayList<>();
        Map<String, Use> best = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line, pkg = null, op = null;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("##")) { pkg = line.substring(2).trim(); op = null; continue; }
                if (pkg == null) continue;
                Matcher om = OP.matcher(line);
                if (om.find()) op = om.group(1);
                Matcher m = OLD_TIME.matcher(line);
                if (!m.find()) {
                    m = NEW_TIME.matcher(line);
                    if (!m.find()) continue;
                }
                String what = op == null ? null : OPS.get(op);
                if (what == null) continue;
                long ms = parseDuration(m.group(1));
                String key = pkg + "|" + what;
                Use old = best.get(key);
                if (old != null && old.agoMs <= ms) continue;
                Use u = new Use();
                u.pkg = pkg;
                u.label = labels.get(pkg);
                u.what = what;
                u.agoMs = ms;
                u.ago = human(ms);
                best.put(key, u);
            }
        }
        p.waitFor();
        out.addAll(best.values());
        out.sort((a, b) -> Long.compare(a.agoMs, b.agoMs));
        return out;
    }

    /**
     * Shizuku.newProcess is private in API 13 (the authors prefer a bound "user service"),
     * but it's stable and far simpler for one read-only command, so call it by reflection.
     */
    private static Process newProcess(String[] cmd) throws Exception {
        Method m = Shizuku.class.getDeclaredMethod("newProcess", String[].class, String[].class, String.class);
        m.setAccessible(true);
        return (Process) m.invoke(null, cmd, null, null);
    }

    /** "1d2h3m4s" -> milliseconds. */
    static long parseDuration(String s) {
        long total = 0, n = 0;
        for (char c : s.toCharArray()) {
            if (Character.isDigit(c)) { n = n * 10 + (c - '0'); continue; }
            switch (c) {
                case 'd': total += n * 86_400_000L; break;
                case 'h': total += n * 3_600_000L; break;
                case 'm': total += n * 60_000L; break;
                case 's': total += n * 1000L; break;
            }
            n = 0;
        }
        return total;
    }

    static String human(long ms) {
        long min = ms / 60_000;
        if (min < 1) return "just now";
        if (min < 60) return min + " min ago";
        long h = min / 60;
        if (h < 24) return h + " h ago";
        return (h / 24) + " days ago";
    }
}
