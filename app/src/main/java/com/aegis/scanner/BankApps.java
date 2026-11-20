package com.aegis.scanner;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Spots fake Indian bank and UPI apps: apps named like SBI, HDFC, PhonePe and so on that were not installed
 * from an app store, plus app ids seen in reported fake-bank campaigns. Real bank and UPI apps come from the
 * Play Store, so a bank-named app installed from a file is the classic banking-trojan lure.
 * Pure Java so it can be unit-tested.
 */
public final class BankApps {

    /** Official app ids of major Indian bank and payment apps (as published on Google Play). */
    static final Set<String> OFFICIAL = new HashSet<>(Arrays.asList(
            "com.sbi.lotusintouch",                     // SBI YONO
            "com.sbi.SBIFreedomPlus",                   // YONO Lite SBI
            "com.sbi.upi",                              // BHIM SBI Pay
            "com.snapwork.hdfc",                        // HDFC Bank
            "com.csam.icici.bank.imobile",              // ICICI iMobile Pay
            "com.axis.mobile",                          // Axis Mobile
            "com.msf.kbank.mobile",                     // Kotak
            "com.Version1",                             // PNB ONE
            "com.bankofbaroda.mconnect",                // bob World
            "com.canarabank.mobility",                  // Canara ai1
            "com.idfcfirstbank.optimus",                // IDFC FIRST
            "net.one97.paytm",                          // Paytm
            "com.phonepe.app",                          // PhonePe
            "com.google.android.apps.nbu.paisa.user",   // Google Pay
            "in.org.npci.upiapp",                       // BHIM
            "com.dreamplug.androidapp",                 // CRED
            "com.mobikwik_new"                          // MobiKwik
    ));

    /** App ids from reported fake-bank and SMS-stealer campaigns in India (Cyble, Zscaler). */
    static final Set<String> KNOWN_FAKE = new HashSet<>(Arrays.asList(
            "in.sbi.rewards",
            "com.sbi.complaintregister",
            "com.example.complaintregisters"
    ));

    private static final Pattern BRAND = Pattern.compile(
            "\\b(sbi|yono|hdfc|icici|axis|kotak|pnb|baroda|bob world|canara|union bank|idfc|indusind|yes bank|"
                    + "paytm|phone ?pe|google pay|gpay|bhim|cred|mobikwik|net ?banking|bank)\\b",
            Pattern.CASE_INSENSITIVE);

    private BankApps() { }

    /** The bank or payment brand an app's name points to, or null. */
    static String brandIn(String label) {
        if (label == null) return null;
        Matcher m = BRAND.matcher(label.replaceAll("[_.\\-]+", " "));
        return m.find() ? m.group(1).toUpperCase(Locale.ROOT) : null;
    }

    /**
     * Why this app looks like a fake bank or UPI app, or null if it doesn't.
     * @param fromStore true if a store installed it (store-hosted bank apps are left to the store's review)
     */
    static String fakeReason(String label, String pkg, boolean fromStore) {
        if (KNOWN_FAKE.contains(pkg)) {
            return "Its app id (" + pkg + ") belongs to a reported fake-bank app that steals OTPs and card details.";
        }
        if (fromStore || OFFICIAL.contains(pkg)) return null;
        String brand = brandIn(label);
        if (brand == null) return null;
        return "It's named like a bank or payment app (\"" + label + "\", " + brand + ") but was installed from a file, "
                + "not the Play Store, and its app id (" + pkg + ") isn't the official one. Real bank and UPI apps "
                + "only come from the Play Store.";
    }
}
