package com.aegis.scanner;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * "On a call" warning: the classic Indian bank-officer / police / customer-care scam keeps you on the phone
 * while you open a UPI, bank or screen-sharing app. If one of those comes to the front during a call, Aegis
 * warns once per app per call. Decision logic is pure Java so it can be unit-tested; the call and app
 * watching lives in {@link ScamAlertService}.
 */
public final class CallGuard {

    static final String PREF_ON = "call_guard_on";

    /** Extra money apps not in BankApps.OFFICIAL. */
    private static final Set<String> EXTRA = new HashSet<>(Arrays.asList(
            "com.sbi.yonobusiness", "com.icicibank.pockets", "com.hdfcbank.payzapp", "com.enstage.wibmo.hdfc",
            "com.freecharge.android", "in.amazon.mShop.android.shopping"
    ));

    private final Set<String> warnedThisCall = new HashSet<>();

    private CallGuard() { }

    static CallGuard newCall() { return new CallGuard(); }

    /** What kind of risky app this is during a call, or null for any other app. */
    static String kind(String pkg) {
        if (pkg == null) return null;
        if (Scanner.REMOTE_APPS.containsKey(pkg)) return "screen-sharing";
        if (BankApps.OFFICIAL.contains(pkg) || EXTRA.contains(pkg)) return "money";
        return null;
    }

    /** True the first time a risky app comes to the front during this call. */
    boolean shouldWarn(String pkg) {
        return kind(pkg) != null && warnedThisCall.add(pkg);
    }

    static String title(String label, String kind) {
        return "screen-sharing".equals(kind)
                ? "⚠ On a call and opening " + label + "?"
                : "On a call and opening " + label + "?";
    }

    static String text(String kind) {
        if ("screen-sharing".equals(kind)) {
            return "Never share your screen with someone on a call. Banks, UPI apps, police and customer care never "
                    + "ask for this. If a caller asked you to, hang up now and call 1930.";
        }
        return "If the caller says they're from your bank, police, CBI, a courier or customer care and asked you to "
                + "open this app: hang up. Never share an OTP, enter your UPI PIN to \"receive\" money, or approve a "
                + "request while someone is guiding you on the phone.";
    }
}
