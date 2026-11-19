package com.aegis.scanner;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Known spy-app and malware indicators, merged from three open-source projects:
 *  - AssoEchap/stalkerware-indicators (CC BY 4.0)
 *      ioc.yaml   : package names, signing-certificate SHA-1s, websites and command servers
 *      samples.csv: SHA-256 hashes of known spy-app APK files
 *  - android-sigma-rules/rules ioc-data, used by AndroDR (CC BY 4.0)
 *      androdr_*.yml: package names, certificate SHA-256s, APK hashes, command-server domains
 *  - mvt-project/mvt-indicators (Amnesty, Citizen Lab and others): Pegasus, Predator and other
 *      government-grade spyware, converted to mvt_iocs.tsv (kind, value, family)
 *
 * A bundled copy ships inside the app; "Update database" downloads fresh copies.
 */
public class IocDb {

    public static final String IOC_URL =
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml";
    public static final String SAMPLES_URL =
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv";
    public static final String ANDRODR_BASE =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/";
    /** AndroDR file names; stored on the phone with an "androdr_" prefix. */
    public static final String[] ANDRODR_FILES =
            {"package-names.yml", "cert-hashes.yml", "malware-hashes.yml", "c2-domains.yml"};
    public static final String MVT_INDEX_URL =
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml";
    public static final String MVT_FILE = "mvt_iocs.tsv";

    /** package name -> spy family name */
    public final Map<String, String> packages = new HashMap<>();
    /** signing certificate SHA-1 or SHA-256 (upper-case hex) -> family */
    public final Map<String, String> certs = new HashMap<>();
    /** APK SHA-256 (lower-case hex) -> family */
    public final Map<String, String> hashes = new HashMap<>();
    /** website / server domain (lower-case) -> family */
    public final Map<String, String> domains = new HashMap<>();

    public final Set<String> families = new HashSet<>();

    public static IocDb load(Context ctx) {
        IocDb db = new IocDb();
        try (InputStream in = open(ctx, "ioc.yaml")) {
            db.parseYaml(in);
        } catch (Exception ignored) { }
        try (InputStream in = open(ctx, "samples.csv")) {
            db.parseSamples(in);
        } catch (Exception ignored) { }
        for (String f : ANDRODR_FILES) {
            try (InputStream in = open(ctx, "androdr_" + f)) {
                db.parseAndroDr(in, f);
            } catch (Exception ignored) { }
        }
        try (InputStream in = open(ctx, MVT_FILE)) {
            db.parseMvt(in);
        } catch (Exception ignored) { }
        return db;
    }

    /** Prefer a downloaded (newer) copy in app storage, otherwise the bundled one. */
    static InputStream open(Context ctx, String name) throws Exception {
        File f = new File(ctx.getFilesDir(), name);
        if (f.exists() && f.length() > 1000) return new FileInputStream(f);
        return ctx.getAssets().open(name);
    }

    /** Small purpose-built reader for the ioc.yaml layout (no YAML library needed). */
    void parseYaml(InputStream in) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String family = null;
        String key = null;
        String line;
        while ((line = r.readLine()) != null) {
            if (line.trim().isEmpty() || line.trim().startsWith("#")) continue;

            // Entries start with "- name: X" (some files write "- name : X").
            if (line.startsWith("- name") && line.indexOf(':') > 0
                    && line.substring(6, line.indexOf(':')).trim().isEmpty()) {
                family = clean(line.substring(line.indexOf(':') + 1));
                families.add(family);
                key = null;
                continue;
            }
            if (family == null) continue;

            int indent = 0;
            while (indent < line.length() && line.charAt(indent) == ' ') indent++;
            String body = line.trim();

            if (body.startsWith("- ")) {
                String value = clean(body.substring(2));
                if (value.isEmpty() || key == null) continue;
                // List items may be indented 2 or 4 spaces under their key.
                if (key.equals("packages")) {
                    packages.put(value, family);
                } else if (key.equals("certificates")) {
                    certs.put(value.toUpperCase(Locale.ROOT).replace(":", ""), family);
                } else if (key.equals("websites") || key.equals("distribution")) {
                    addDomain(value, family);
                } else if (key.equals("c2.domains")) {
                    addDomain(value, family);
                }
                continue;
            }

            int colon = body.indexOf(':');
            if (colon > 0) {
                String k = body.substring(0, colon).trim();
                String rest = body.substring(colon + 1).trim();
                if (indent == 2) {
                    key = rest.isEmpty() ? k : null;
                } else if (indent == 4 && key != null && (key.equals("c2") || key.startsWith("c2."))) {
                    key = "c2." + k;
                }
            }
        }
    }

    private void addDomain(String value, String family) {
        String d = value.toLowerCase(Locale.ROOT);
        if (d.startsWith("http://")) d = d.substring(7);
        if (d.startsWith("https://")) d = d.substring(8);
        int slash = d.indexOf('/');
        // A full URL (e.g. github.com/someone/project) points at one page on a shared site.
        // Flagging the whole site would be a false alarm, so skip those.
        if (slash > 0 && slash < d.length() - 1) return;
        if (slash > 0) d = d.substring(0, slash);
        if (d.startsWith("www.")) d = d.substring(4);
        if (d.contains(".") && !d.matches("[0-9.]+")) domains.put(d, family);
    }

    void parseSamples(InputStream in) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        boolean header = true;
        while ((line = r.readLine()) != null) {
            if (header) { header = false; continue; }
            String[] p = line.split(",");
            if (p.length >= 5 && p[0].length() == 64) {
                String fam = p[4].trim();
                hashes.put(p[0].trim().toLowerCase(Locale.ROOT), fam);
                if (p[1].trim().length() > 2) packages.putIfAbsent(p[1].trim(), fam);
                if (p[2].trim().length() == 40) certs.putIfAbsent(p[2].trim().toUpperCase(Locale.ROOT), fam);
            }
        }
    }

    /**
     * Reads one AndroDR ioc-data file: a list of "- indicator: X" blocks with family, category
     * and severity. Skips data-broker / proxy SDK domains and MEDIUM-severity entries, which are
     * privacy concerns rather than spy apps and would cause false "Act now" alarms.
     */
    void parseAndroDr(InputStream in, String file) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String[] cur = null; // indicator, family, category, severity
        String line;
        while (true) {
            line = r.readLine();
            String t = line == null ? null : line.trim();
            if (t == null || t.startsWith("- indicator:")) {
                if (cur != null) addAndroDr(cur, file);
                if (t == null) break;
                cur = new String[]{clean(t.substring(12)), null, "", ""};
            } else if (cur != null && t.startsWith("family:")) {
                cur[1] = clean(t.substring(7));
            } else if (cur != null && t.startsWith("category:")) {
                cur[2] = clean(t.substring(9));
            } else if (cur != null && t.startsWith("severity:")) {
                cur[3] = clean(t.substring(9));
            }
        }
    }

    private void addAndroDr(String[] e, String file) {
        String value = e[0], cat = e[2];
        if (value.isEmpty() || e[1] == null || e[1].isEmpty()) return;
        if (cat.equals("DATA_BROKER_SDK") || cat.equals("PROXYWARE") || cat.equals("FORENSIC_TOOL")
                || e[3].equals("MEDIUM")) return;
        String fam = cat.equals("MALWARE") ? e[1] + " malware" : e[1];
        families.add(fam);
        switch (file) {
            case "package-names.yml": packages.putIfAbsent(value, fam); break;
            case "cert-hashes.yml": certs.putIfAbsent(value.toUpperCase(Locale.ROOT).replace(":", ""), fam); break;
            case "malware-hashes.yml": if (value.length() == 64) hashes.putIfAbsent(value.toLowerCase(Locale.ROOT), fam); break;
            case "c2-domains.yml": addDomain(value, fam); break;
        }
    }

    /** Reads mvt_iocs.tsv lines: kind (app|cert|hash|domain), value, family. */
    void parseMvt(InputStream in) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            String[] p = line.split("\t");
            if (p.length < 3 || line.startsWith("#")) continue;
            String v = p[1].trim(), fam = p[2].trim();
            families.add(fam);
            switch (p[0]) {
                case "app": packages.putIfAbsent(v, fam); break;
                case "cert": certs.putIfAbsent(v.toUpperCase(Locale.ROOT).replace(":", ""), fam); break;
                case "hash": hashes.putIfAbsent(v.toLowerCase(Locale.ROOT), fam); break;
                case "domain": addDomain(v, fam); break;
            }
        }
    }

    /**
     * Converts one MVT STIX2 file into mvt_iocs.tsv lines. Only indicators an app can check
     * on the phone are kept: app ids, signing certificates, APK hashes and domains.
     */
    static void stixToTsv(String json, String family, StringBuilder out) throws Exception {
        org.json.JSONArray objects = new org.json.JSONObject(json).optJSONArray("objects");
        if (objects == null) return;
        java.util.regex.Pattern pat = java.util.regex.Pattern.compile("^\\[([a-z0-9:._-]+)\\s*=\\s*'([^']+)'\\]$");
        for (int i = 0; i < objects.length(); i++) {
            org.json.JSONObject o = objects.optJSONObject(i);
            if (o == null || !"indicator".equals(o.optString("type"))) continue;
            java.util.regex.Matcher m = pat.matcher(o.optString("pattern"));
            if (!m.matches()) continue;
            String kind;
            switch (m.group(1)) {
                case "app:id": kind = "app"; break;
                case "app:cert.sha1": case "app:cert.sha256": kind = "cert"; break;
                case "file:hashes.sha256": kind = "hash"; break;
                case "domain-name:value": kind = "domain"; break;
                default: continue;
            }
            out.append(kind).append('\t').append(m.group(2).trim()).append('\t').append(family).append('\n');
        }
    }

    /** Returns the family if this host (or any parent domain) is a known spy-app site. */
    public String matchDomain(String host) {
        if (host == null) return null;
        String h = host.toLowerCase(Locale.ROOT);
        while (h.contains(".")) {
            String fam = domains.get(h);
            if (fam != null) return fam;
            h = h.substring(h.indexOf('.') + 1);
        }
        return null;
    }

    private static String clean(String s) {
        s = s.trim();
        if (s.length() >= 2 && ((s.startsWith("'") && s.endsWith("'"))
                || (s.startsWith("\"") && s.endsWith("\"")))) {
            s = s.substring(1, s.length() - 1);
        }
        return s.trim();
    }
}
