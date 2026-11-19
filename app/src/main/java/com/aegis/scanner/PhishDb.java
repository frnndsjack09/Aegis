package com.aegis.scanner;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Offline list of known phishing domains, checked by the link and message checkers.
 *  - malware-filter phishing-filter (OpenPhish, PhishTank, IPThreat; CC BY-SA 4.0): bundled, refreshed by "Update"
 *  - Phishing.Army (PhishTank, OpenPhish, CERT.PL and others; free for personal protection): downloaded by "Update" only
 */
public final class PhishDb {

    public static final String[][] SOURCES = {
            {"phishing_domains.txt", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt"},
            {"phishing_army.txt", "https://phishing.army/download/phishing_army_blocklist.txt"},
    };

    private static Set<String> cache;
    private static long cacheStamp = -1;

    /** Loads (or reuses) the merged list. ~170k domains, so it's kept in memory once loaded. */
    public static synchronized Set<String> load(Context ctx) {
        long stamp = 0;
        for (String[] s : SOURCES) stamp += new File(ctx.getFilesDir(), s[0]).lastModified();
        if (cache != null && stamp == cacheStamp) return cache;
        Set<String> set = new HashSet<>();
        for (String[] s : SOURCES) {
            try (InputStream in = IocDb.open(ctx, s[0])) {
                read(in, set);
            } catch (Exception ignored) { } // Phishing.Army has no bundled copy until the first update
        }
        cache = set;
        cacheStamp = stamp;
        return set;
    }

    static void read(InputStream in, Set<String> set) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            String d = line.trim().toLowerCase(Locale.ROOT);
            if (d.isEmpty() || d.startsWith("#")) continue;
            if (d.startsWith("www.")) d = d.substring(4);
            set.add(d);
        }
    }

    /** True if this host or any parent domain is listed. */
    public static boolean matches(Set<String> set, String host) {
        if (set == null || host == null) return false;
        String h = host.toLowerCase(Locale.ROOT);
        while (h.contains(".")) {
            if (set.contains(h)) return true;
            h = h.substring(h.indexOf('.') + 1);
        }
        return false;
    }

    /** Lines that look like domains, for checking a download before replacing the old copy. */
    static int countDomains(File f) {
        Set<String> s = new HashSet<>();
        try (InputStream in = new java.io.FileInputStream(f)) {
            read(in, s);
        } catch (Exception e) {
            return 0;
        }
        return s.size();
    }
}
