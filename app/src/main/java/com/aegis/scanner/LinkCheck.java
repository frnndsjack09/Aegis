package com.aegis.scanner;

import android.net.Uri;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Checks a link for common scam tricks, known spy-app sites and (with a key) the URLhaus database. */
public class LinkCheck {

    public static class Result {
        public String text;
        public boolean danger, warnings;
    }

    private static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "tiny.cc",
            "ow.ly", "rebrand.ly", "t.ly", "s.id", "goo.su", "shorte.st", "bitly.com"));

    private static final Set<String> RISKY_TLDS = new HashSet<>(Arrays.asList(
            "zip", "mov", "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
            "icu", "buzz", "rest", "cam", "monster", "cyou", "sbs", "lol", "quest"));

    /** Brand word -> official domains. Used to spot fake bank / payment / government sites. */
    private static final String[][] BRANDS = {
            {"sbi", "onlinesbi.sbi", "sbi.co.in", "sbi.bank.in", "sbicard.com", "sbilife.co.in"},
            {"hdfc", "hdfcbank.com", "hdfc.bank.in", "hdfclife.com", "hdfcergo.com"},
            {"icici", "icicibank.com", "icici.bank.in", "iciciprulife.com", "icicilombard.com"},
            {"axis", "axisbank.com", "axis.bank.in"},
            {"kotak", "kotak.com", "kotak.bank.in"},
            {"paytm", "paytm.com", "paytmbank.com", "paytm.in"},
            {"phonepe", "phonepe.com"},
            {"gpay", "pay.google.com"},
            {"amazon", "amazon.in", "amazon.com", "amazonpay.in"},
            {"flipkart", "flipkart.com"},
            {"whatsapp", "whatsapp.com", "whatsapp.net", "wa.me"},
            {"google", "google.com", "google.co.in", "goo.gl", "g.co", "googleusercontent.com",
                    "googleapis.com", "googlevideo.com", "googleblog.com"},
            {"incometax", "incometax.gov.in"},
            {"epfo", "epfindia.gov.in"},
            {"uidai", "uidai.gov.in"},
            {"aadhaar", "uidai.gov.in"},
            {"npci", "npci.org.in"},
            {"irctc", "irctc.co.in"},
            {"indiapost", "indiapost.gov.in"},
    };

    public static Result check(String raw, IocDb ioc, Set<String> phishing, String abuseKey) {
        Result r = new Result();
        List<String> bad = new ArrayList<>();
        List<String> warn = new ArrayList<>();

        String url = raw.trim();
        if (!url.contains("://")) url = "http://" + url;
        Uri u = Uri.parse(url);
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) {
            r.text = "That doesn't look like a web link.";
            r.warnings = true;
            return r;
        }
        if (host.startsWith("www.")) host = host.substring(4);

        String fam = ioc.matchDomain(host);
        if (fam != null) bad.add("This is a website or server of \"" + fam + "\" (spy app or malware).");
        if (PhishDb.matches(phishing, host)) {
            bad.add("Listed as a phishing, scam or malware site in public blocklists (OpenPhish, PhishTank, Phishing Army, HaGeZi).");
        }

        if ("http".equals(u.getScheme()) && raw.trim().toLowerCase(Locale.ROOT).startsWith("http://")) {
            warn.add("Not encrypted (http, not https). Never type passwords or card details here.");
        }
        if (host.matches("[0-9.]+") || host.contains(":")) {
            warn.add("Uses a raw number address instead of a name. Real banks and shops never do this.");
        }
        if (host.contains("xn--")) {
            warn.add("Uses look-alike letters (e.g. a Russian 'а' instead of 'a') to imitate another site.");
        }
        if (SHORTENERS.contains(host)) {
            warn.add("Shortened link: it hides where it really goes. Be careful.");
        }
        int dot = host.lastIndexOf('.');
        String tld = dot >= 0 ? host.substring(dot + 1) : "";
        if (RISKY_TLDS.contains(tld)) {
            warn.add("Ends in \"." + tld + "\", a domain type often used by scam sites.");
        }
        if (u.getEncodedAuthority() != null && u.getEncodedAuthority().contains("@")) {
            bad.add("Contains an '@' trick: the real site is \"" + host + "\", not what appears before the '@'.");
        }
        if (host.split("\\.").length > 5) {
            warn.add("Has an unusually long chain of sub-domains, a common way to imitate real sites.");
        }

        for (String[] b : BRANDS) {
            // "axis" also appears inside ordinary words (e.g. "taxis"), so require it to start a name part.
            boolean mentions = b[0].equals("axis")
                    ? host.matches("(.*[.-])?axis.*")
                    : host.contains(b[0]);
            if (!mentions) continue;
            boolean official = host.endsWith(".gov.in") || host.endsWith(".nic.in");
            for (int i = 1; i < b.length && !official; i++) {
                if (host.equals(b[i]) || host.endsWith("." + b[i])) official = true;
            }
            if (!official) {
                bad.add("Mentions \"" + b[0].toUpperCase(Locale.ROOT) + "\" but \"" + host
                        + "\" is not its official website. Likely a fake.");
            }
        }

        String urlhaus = null;
        if (abuseKey != null && !abuseKey.isEmpty()) {
            try {
                urlhaus = Net.urlhausCheck(raw.trim().contains("://") ? raw.trim() : url, abuseKey);
                if (urlhaus.startsWith("LISTED")) bad.add(urlhaus);
            } catch (Exception e) {
                urlhaus = "URLhaus check failed: " + e.getMessage();
            }
        }

        StringBuilder sb = new StringBuilder("Website: " + host + "\n\n");
        if (!bad.isEmpty()) {
            r.danger = true;
            sb.insert(0, "⚠ DANGEROUS. Don't open it.\n");
            for (String s : bad) sb.append("✗ ").append(s).append('\n');
        }
        if (!warn.isEmpty()) {
            r.warnings = true;
            if (bad.isEmpty()) sb.insert(0, "Be careful with this link.\n");
            for (String s : warn) sb.append("! ").append(s).append('\n');
        }
        if (bad.isEmpty() && warn.isEmpty()) {
            sb.insert(0, "✓ No warning signs found.\n");
            sb.append("That doesn't guarantee it's safe. Never enter OTPs or PINs on a page you reached from a message.\n");
        }
        if (urlhaus != null && !urlhaus.startsWith("LISTED")) sb.append('\n').append(urlhaus);
        else if (abuseKey == null || abuseKey.isEmpty()) sb.append("\n(Add an abuse.ch key in Tools for a malware-database check too.)");
        r.text = sb.toString().trim();
        return r;
    }
}
