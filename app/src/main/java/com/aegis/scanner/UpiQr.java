package com.aegis.scanner;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Explains what a payment QR code really does. The "scan this QR to receive money" scam (OLX/Quikr sellers,
 * fake refunds, prizes) works because people don't know that paying a UPI QR always SENDS money.
 * Pure Java so it can be unit-tested.
 */
public final class UpiQr {

    public static final class Result {
        public boolean upi;
        public String payee = "", name = "", amount = "", note = "";
        public Finding.Level level = Finding.Level.GREEN;
        public String headline = "";
        public final List<String> reasons = new ArrayList<>();
        /** For non-UPI QR codes that hold a web link, the link to check. */
        public String link;
    }

    private static final Pattern RECEIVE_LURE = Pattern.compile(
            "\\b(refund|cash ?back|prize|reward|receive|lottery|winning|won\\b|gift|bonus|kyc|verify|claim|credited|return|"
                    + "paise milenge|paisa milega)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern AUTHORITY = Pattern.compile(
            "customer ?care|support|helpline|police|cbi|cyber ?cell|court|electricity|bijli|income ?tax|rbi|npci|"
                    + "government|govt|sarkar",
            Pattern.CASE_INSENSITIVE);

    private UpiQr() { }

    public static Result explain(String text) {
        Result r = new Result();
        String t = text == null ? "" : text.trim();
        if (!t.toLowerCase(Locale.ROOT).startsWith("upi://")) {
            if (t.matches("(?is)^(https?://|www\\.).*")) {
                r.link = t;
                r.level = Finding.Level.INFO;
                r.headline = "This QR code opens a website";
                r.reasons.add("Link: " + t);
            } else {
                r.level = Finding.Level.INFO;
                r.headline = "This QR code holds text, not a payment";
                r.reasons.add(t.length() > 300 ? t.substring(0, 300) + "…" : t);
            }
            return r;
        }

        r.upi = true;
        Map<String, String> q = query(t);
        r.payee = q.getOrDefault("pa", "");
        r.name = q.getOrDefault("pn", "");
        r.amount = q.getOrDefault("am", "");
        r.note = q.getOrDefault("tn", "");

        String who = r.name.isEmpty() ? r.payee : r.name + " (" + r.payee + ")";
        r.reasons.add("Paying this QR SENDS money from your account to " + (who.isEmpty() ? "an unknown account" : who)
                + ". Scanning a QR code can never put money into your account.");
        boolean lure = RECEIVE_LURE.matcher(r.note + " " + r.name).find();
        boolean authority = AUTHORITY.matcher(r.name + " " + r.note).find() || BankApps.brandIn(r.name) != null;
        if (!r.amount.isEmpty()) r.reasons.add("It's already set to take ₹" + r.amount + ".");
        if (!r.note.isEmpty()) r.reasons.add("Payment note: \"" + r.note + "\"");
        if (lure) {
            r.reasons.add("It talks about a refund, prize, cashback or receiving money. That's the scam: you'd be paying, not receiving.");
        }
        if (authority) {
            r.reasons.add("The name claims to be a bank, customer care, police or government office. They never collect money through a QR code sent to you.");
        }
        if (lure) {
            r.level = Finding.Level.RED;
            r.headline = "Scam: this QR takes money, it doesn't give it";
        } else if (authority || !r.amount.isEmpty()) {
            r.level = Finding.Level.YELLOW;
            r.headline = "Check before paying";
        } else {
            r.level = Finding.Level.GREEN;
            r.headline = "Normal payment QR";
            r.reasons.add("Before you enter your PIN, make sure the name your UPI app shows is the person or shop you mean to pay.");
        }
        return r;
    }

    static Map<String, String> query(String uri) {
        Map<String, String> m = new HashMap<>();
        int i = uri.indexOf('?');
        if (i < 0) return m;
        for (String part : uri.substring(i + 1).split("&")) {
            int e = part.indexOf('=');
            if (e <= 0) continue;
            String k = part.substring(0, e).toLowerCase(Locale.ROOT), v = part.substring(e + 1);
            try { v = URLDecoder.decode(v, StandardCharsets.UTF_8.name()); } catch (Exception ignored) { }
            m.put(k, v.trim());
        }
        return m;
    }
}
