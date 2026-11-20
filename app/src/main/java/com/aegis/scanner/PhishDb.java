package com.aegis.scanner;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.AbstractSet;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;

/**
 * Offline list of known phishing and malware domains, checked by the link and message checkers.
 *  - malware-filter phishing-filter (OpenPhish, PhishTank, IPThreat; CC BY-SA 4.0): bundled, refreshed by "Update"
 *  - Phishing.Army (PhishTank, OpenPhish, CERT.PL and others; free for personal protection): downloaded by "Update" only
 *  - HaGeZi Threat Intelligence Feeds, mini (malware, phishing, scam and C2 domains; GPL-3.0): downloaded by "Update" only
 * Stored as sorted 64-bit hashes (~8 bytes per domain instead of ~100 for a String in a HashSet),
 * because the scam-alert service keeps the list in memory.
 */
public final class PhishDb {

    public static final String[][] SOURCES = {
            {"phishing_domains.txt", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt"},
            {"phishing_army.txt", "https://phishing.army/download/phishing_army_blocklist.txt"},
            {"hagezi_tif_mini.txt", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"},
    };

    private static Set<String> cache;
    private static long cacheStamp = -1;

    /** Loads (or reuses) the merged list, as a compact read-only set that only supports contains(). */
    public static synchronized Set<String> load(Context ctx) {
        long stamp = 0;
        for (String[] s : SOURCES) stamp += new File(ctx.getFilesDir(), s[0]).lastModified();
        if (cache != null && stamp == cacheStamp) return cache;
        long[] h = new long[1 << 18];
        int n = 0;
        for (String[] s : SOURCES) {
            try (InputStream in = IocDb.open(ctx, s[0])) {
                BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                String line;
                while ((line = r.readLine()) != null) {
                    String d = clean(line);
                    if (d == null) continue;
                    if (n == h.length) h = Arrays.copyOf(h, n * 2);
                    h[n++] = hash(d);
                }
            } catch (Exception ignored) { } // downloaded-only lists have no copy until the first update
        }
        cache = new HashedSet(h, n);
        cacheStamp = stamp;
        return cache;
    }

    /** Normalised domain from one list line, or null for comments and blanks. */
    static String clean(String line) {
        String d = line.trim().toLowerCase(Locale.ROOT);
        if (d.isEmpty() || d.startsWith("#") || d.startsWith("!")) return null;
        if (d.startsWith("www.")) d = d.substring(4);
        return d;
    }

    static void read(InputStream in, Set<String> set) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            String d = clean(line);
            if (d != null) set.add(d);
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

    /** 64-bit FNV-1a. With ~400k domains the chance of any false match is about 1 in 10^8. */
    static long hash(String s) {
        long x = 0xcbf29ce484222325L;
        for (int i = 0; i < s.length(); i++) {
            x ^= s.charAt(i);
            x *= 0x100000001b3L;
        }
        return x;
    }

    /** Read-only set of domain hashes. contains() and size() work; iteration is not needed and not supported. */
    static final class HashedSet extends AbstractSet<String> {
        private final long[] h;

        HashedSet(long[] raw, int n) {
            long[] s = Arrays.copyOf(raw, n);
            Arrays.sort(s);
            int m = 0;
            for (int i = 0; i < s.length; i++) if (i == 0 || s[i] != s[i - 1]) s[m++] = s[i];
            h = Arrays.copyOf(s, m);
        }

        @Override public boolean contains(Object o) {
            return o instanceof String && Arrays.binarySearch(h, hash((String) o)) >= 0;
        }

        @Override public int size() { return h.length; }

        @Override public Iterator<String> iterator() { throw new UnsupportedOperationException(); }
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
