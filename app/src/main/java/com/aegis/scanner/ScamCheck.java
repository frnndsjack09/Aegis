package com.aegis.scanner;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Spots the common tricks in scam SMS / WhatsApp messages seen in India: fake KYC, account or SIM
 * blocking, OTP and UPI-PIN requests, "digital arrest", electricity cut-off, parcel, prize, job and
 * loan offers, app-file and screen-sharing requests. English and common Hinglish wording.
 * Pure Java (no Android classes) so it can be unit-tested.
 */
public final class ScamCheck {

    public static final class Result {
        public final List<String> reasons = new ArrayList<>();
        public final List<String> links = new ArrayList<>();
        public int score;

        /** 3+ = likely scam, 1-2 = be careful, 0 = nothing found. */
        public boolean likelyScam() { return score >= 3; }
    }

    private static final Object[][] RULES = {
            {"\\bkyc\\b.{0,60}(update|expir|pending|block|suspend|verify|incomplete)|(update|complete|verify).{0,30}\\bkyc\\b", 3,
                    "Asks you to update KYC. Banks never ask for KYC through a link, SMS or WhatsApp."},
            {"(account|a/c|khata|card|sim|number|wallet|upi id).{0,40}(block|suspend|deactivat|band ho|close|freez|bar(r)?ed)", 2,
                    "Threatens to block your account, card or SIM. Scammers use fear to rush you."},
            {"(aadhaa?r|\\bpan\\b|pan card).{0,40}(link|update|verify|block|expir|suspend)", 2,
                    "Asks you to link or update Aadhaar/PAN. The government and banks don't do this through messages."},
            {"\\botp\\b.{0,40}(share|send|tell|bata|forward|provide|give)|(share|send|tell|bata|forward|provide|give).{0,30}\\botp\\b", 3,
                    "Asks for an OTP. Never share an OTP with anyone, not even someone who says they're from the bank."},
            {"(enter|daal|dal|type|use).{0,20}(upi )?(pin|mpin).{0,50}(receive|get|credit|refund|cashback|paise|money|amount)|(receive|get|claim).{0,30}(money|amount|refund|cashback).{0,40}\\bpin\\b", 3,
                    "Says you need your UPI PIN to receive money. You never enter a PIN to receive money. Entering it sends money."},
            {"collect request|approve.{0,30}(payment )?request|request.{0,20}(money|payment).{0,20}(approve|accept)", 2,
                    "Mentions approving a payment request. Approving a UPI collect request takes money out of your account."},
            {"(electricity|bijli|power|light).{0,60}(disconnect|cut|kat|band)", 3,
                    "Threatens to cut your electricity tonight. Electricity boards don't send these messages with a personal number."},
            {"digital arrest|(\\bcbi\\b|police|customs|narcotics|\\bncb\\b|\\bed\\b|enforcement directorate|\\btrai\\b|cyber cell|crime branch|court).{0,60}(case|arrest|warrant|parcel|illegal|\\bfir\\b|summon|investigation|money laundering)", 3,
                    "Uses police, CBI, customs or 'digital arrest' threats. There is no such thing as a digital arrest; real agencies don't investigate over calls or video."},
            {"(parcel|courier|fedex|dhl|shipment|india post|package).{0,60}(held|seized|customs|drugs|pending|address|fee|charge|return)", 2,
                    "Says a parcel is held or needs a fee. A common trick to get card details or install a fake app."},
            {"(won|winner|lottery|lucky draw|prize|cashback|reward|gift|kbc).{0,60}(claim|rs\\.?|₹|inr|lakh|crore|congratulation)|congratulations.{0,60}(won|selected|winner)", 2,
                    "Promises a prize, lottery or cashback. You can't win a contest you didn't enter."},
            {"(work from home|part.?time|daily income|earn|kamao).{0,40}(rs\\.?|₹|inr|per day|daily|weekly|per task)|(like|rate|review|subscribe).{0,30}(videos?|hotels?|products?|channels?).{0,40}(earn|paid|income|rs|₹)", 2,
                    "Offers easy money for simple tasks. These end with you paying a 'deposit' you never get back."},
            {"loan.{0,40}(approved|pre.?approved|instant|sanctioned|disburs)", 1,
                    "Offers a loan you didn't apply for. Fake loan apps steal contacts and photos to blackmail people."},
            {"(income tax|\\bit dept|tax dept|tax).{0,40}refund", 2,
                    "Promises a tax refund. The Income Tax department pays refunds directly to your bank, without links."},
            {"\\.apk\\b|(download|install).{0,40}(this )?app.{0,30}(link|from|below|given)", 3,
                    "Asks you to install an app from a link or file (.apk). This is how phones get spy apps and banking malware."},
            {"anydesk|teamviewer|quick ?support|rustdesk|airdroid|screen ?shar", 3,
                    "Mentions a screen-sharing app. Scammers use these to watch and control your phone."},
            {"(card number|\\bcvv\\b|expiry date|net ?banking password|\\bmpin\\b|atm pin|debit card details)", 3,
                    "Asks for card or banking details. No real company asks for these by message."},
            {"urgent|immediately|turant|jaldi|within \\d+ ?(hours?|hrs?|minutes?|mins?)|today itself|last (date|chance|warning)|aaj hi|tonight", 1,
                    "Pushes you to act immediately. Pressure is the main tool of every scam."},
            {"(call|whatsapp|contact|sampark).{0,25}(\\+?91[\\s-]?)?[6-9]\\d{4}[\\s-]?\\d{5}", 1,
                    "Asks you to call or WhatsApp a personal mobile number. Real companies use official numbers."},
    };

    private static final Pattern[] PATTERNS = new Pattern[RULES.length];
    static {
        for (int i = 0; i < RULES.length; i++) {
            PATTERNS[i] = Pattern.compile((String) RULES[i][0], Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        }
    }

    private static final Pattern LINK = Pattern.compile(
            "(https?://[^\\s<>\"]+|www\\.[^\\s<>\"]+|\\b[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9-]+)*\\.(?:com|in|net|org|info|co|me|ly|gl|io|app|link|site|online|live|shop|club|cc|xyz|top|click|loan|work|tk|ml|ga|cf|gq|icu|buzz|cyou|sbs|lol|quest|rest|cam|monster|zip|mov)\\b(?:/[^\\s<>\"]*)?)",
            Pattern.CASE_INSENSITIVE);

    public static Result check(String message) {
        Result r = new Result();
        if (message == null) return r;
        String text = message.replace('\n', ' ');
        String lower = text.toLowerCase(Locale.ROOT);
        for (int i = 0; i < RULES.length; i++) {
            if (PATTERNS[i].matcher(lower).find()) {
                r.score += (Integer) RULES[i][1];
                r.reasons.add((String) RULES[i][2]);
            }
        }
        Set<String> links = new LinkedHashSet<>();
        Matcher m = LINK.matcher(text);
        while (m.find() && links.size() < 5) {
            if (m.start() > 0 && text.charAt(m.start() - 1) == '@') continue; // domain part of an e-mail address
            links.add(m.group(1).replaceAll("[.,;:!?)\\]'\"]+$", ""));
        }
        r.links.addAll(links);
        return r;
    }
}
