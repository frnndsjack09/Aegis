package com.aegis.scanner;

import android.content.Context;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Everything that touches the internet. Nothing runs unless you tap a button.
 *  - Password leak check: Have I Been Pwned "range" API (only 5 characters of a hash leave the phone)
 *  - Link check: abuse.ch URLhaus (needs a free abuse.ch Auth-Key)
 *  - App hash check: abuse.ch MalwareBazaar (same free key)
 *  - Database updates from GitHub / Exodus Privacy
 */
public class Net {

    private static final String UA = "Aegis-Android/1.0";

    static String get(String url, String headerName, String headerValue) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setRequestProperty("User-Agent", UA);
        if (headerName != null) c.setRequestProperty(headerName, headerValue);
        try {
            int code = c.getResponseCode();
            if (code != 200) throw new Exception("Server answered " + code);
            try (InputStream in = c.getInputStream()) {
                return TrackerDb.readAll(in);
            }
        } finally {
            c.disconnect();
        }
    }

    static String postForm(String url, String form, String authKey) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setDoOutput(true);
        c.setRequestMethod("POST");
        c.setRequestProperty("User-Agent", UA);
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        if (authKey != null && !authKey.isEmpty()) c.setRequestProperty("Auth-Key", authKey);
        try {
            try (OutputStream o = c.getOutputStream()) {
                o.write(form.getBytes(StandardCharsets.UTF_8));
            }
            int code = c.getResponseCode();
            if (code == 401 || code == 403) throw new Exception("The abuse.ch key was rejected (" + code + ")");
            if (code != 200) throw new Exception("Server answered " + code);
            try (InputStream in = c.getInputStream()) {
                return TrackerDb.readAll(in);
            }
        } finally {
            c.disconnect();
        }
    }

    /** Downloads a URL into the app's private storage. Returns the byte count. */
    static long download(Context ctx, String url, String fileName) throws Exception {
        return save(ctx, fileName, get(url, null, null));
    }

    /** Writes text to app storage via a temp file, so a failed write never leaves half a database. */
    static long save(Context ctx, String fileName, String body) throws Exception {
        File tmp = new File(ctx.getFilesDir(), fileName + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(body.getBytes(StandardCharsets.UTF_8));
        }
        File dest = new File(ctx.getFilesDir(), fileName);
        if (!tmp.renameTo(dest)) throw new Exception("Could not save " + fileName);
        return dest.length();
    }

    /**
     * How many times this password appears in known data breaches (0 = not found).
     * Only the first 5 characters of the password's SHA-1 hash are sent.
     */
    public static int pwnedPasswordCount(String password) throws Exception {
        String sha1 = hex(MessageDigest.getInstance("SHA-1")
                .digest(password.getBytes(StandardCharsets.UTF_8))).toUpperCase(Locale.ROOT);
        String prefix = sha1.substring(0, 5);
        String suffix = sha1.substring(5);
        String body = get("https://api.pwnedpasswords.com/range/" + prefix, "Add-Padding", "true");
        for (String line : body.split("\n")) {
            String[] p = line.trim().split(":");
            if (p.length == 2 && p[0].equalsIgnoreCase(suffix)) {
                int n = Integer.parseInt(p[1].trim());
                if (n > 0) return n;
            }
        }
        return 0;
    }

    /** URLhaus lookup. Returns a human sentence. */
    public static String urlhausCheck(String url, String key) throws Exception {
        String body = postForm("https://urlhaus-api.abuse.ch/v1/url/",
                "url=" + URLEncoder.encode(url, "UTF-8"), key);
        JSONObject j = new JSONObject(body);
        String status = j.optString("query_status");
        if ("ok".equals(status)) {
            String threat = j.optString("threat", "malware");
            String state = j.optString("url_status", "");
            return "LISTED as malicious in URLhaus (" + threat
                    + (state.isEmpty() ? "" : ", currently " + state) + ").";
        }
        if ("no_results".equals(status)) return "Not listed in URLhaus.";
        return "URLhaus answered: " + status;
    }

    /** MalwareBazaar lookup for one SHA-256. Returns the malware name, or null if unknown. */
    public static String malwareBazaar(String sha256, String key) throws Exception {
        String body = postForm("https://mb-api.abuse.ch/api/v1/",
                "query=get_info&hash=" + sha256, key);
        JSONObject j = new JSONObject(body);
        String status = j.optString("query_status");
        if ("ok".equals(status)) {
            String sig = "known malware";
            try {
                JSONObject first = j.getJSONArray("data").getJSONObject(0);
                String s = first.optString("signature", "");
                if (!s.isEmpty() && !"null".equals(s)) sig = s;
            } catch (Exception ignored) { }
            return sig;
        }
        if ("hash_not_found".equals(status) || "no_results".equals(status)) return null;
        if (status.contains("auth") || status.contains("unknown")) {
            throw new Exception("MalwareBazaar: " + status);
        }
        return null;
    }

    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format(Locale.ROOT, "%02x", x));
        return sb.toString();
    }
}
