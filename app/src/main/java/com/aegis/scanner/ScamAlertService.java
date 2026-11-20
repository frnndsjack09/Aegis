package com.aegis.scanner;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.provider.Settings;
import android.provider.Telephony;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Scam alerts: reads new SMS, WhatsApp and Telegram notifications, runs the offline scam checker on them,
 * and warns when a message looks like a scam. Message text stays in memory only: it is never stored,
 * logged or sent anywhere. Only runs while the user has granted Notification access.
 * While connected it also runs the new-app check the moment an app is installed.
 */
public class ScamAlertService extends NotificationListenerService {

    private static final Set<String> MESSAGING = new HashSet<>(Arrays.asList(
            "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "org.thunderdog.challegram",
            "com.google.android.apps.messaging", "com.android.mms", "com.android.messaging",
            "com.samsung.android.messaging", "com.truecaller", "com.facebook.orca",
            "com.instagram.android", "com.microsoft.android.smsorganizer"));

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    /** Hashes of recently checked messages, so a re-posted notification doesn't alert twice. */
    private final Map<Integer, Boolean> recent = Collections.synchronizedMap(new LinkedHashMap<Integer, Boolean>() {
        @Override protected boolean removeEldestEntry(Map.Entry<Integer, Boolean> e) { return size() > 200; }
    });
    private IocDb ioc;
    private Set<String> phish;
    private String smsApp;
    private boolean receiverOn;

    private final BroadcastReceiver installs = new BroadcastReceiver() {
        @Override public void onReceive(Context c, Intent i) {
            worker.execute(() -> Guard.checkChanged(getApplicationContext()));
        }
    };

    public static boolean isEnabled(Context ctx) {
        String s = Settings.Secure.getString(ctx.getContentResolver(), "enabled_notification_listeners");
        return s != null && s.contains(new ComponentName(ctx, ScamAlertService.class).flattenToString());
    }

    @Override
    public void onListenerConnected() {
        smsApp = Telephony.Sms.getDefaultSmsPackage(this);
        IntentFilter f = new IntentFilter(Intent.ACTION_PACKAGE_ADDED);
        f.addAction(Intent.ACTION_PACKAGE_REPLACED);
        f.addDataScheme("package");
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(installs, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(installs, f);
        receiverOn = true;
    }

    @Override
    public void onListenerDisconnected() {
        if (receiverOn) { unregisterReceiver(installs); receiverOn = false; }
    }

    @Override
    public void onDestroy() {
        onListenerDisconnected();
        worker.shutdown();
        super.onDestroy();
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        String pkg = sbn.getPackageName();
        if (!MESSAGING.contains(pkg) && !pkg.equals(smsApp)) return;
        Notification n = sbn.getNotification();
        if ((n.flags & (Notification.FLAG_GROUP_SUMMARY | Notification.FLAG_ONGOING_EVENT)) != 0) return;
        Bundle x = n.extras;
        if (x == null) return;
        CharSequence title = x.getCharSequence(Notification.EXTRA_TITLE);
        String body = lastMessage(x);
        if (body == null || body.length() < 12) return;
        int key = (pkg + body).hashCode();
        if (recent.put(key, Boolean.TRUE) != null) return;
        String sender = title == null ? "a message" : title.toString();
        worker.execute(() -> check(sender, body));
    }

    /** The newest message text: MessagingStyle's last message if present, else the big or normal text. */
    private static String lastMessage(Bundle x) {
        Parcelable[] msgs = x.getParcelableArray(Notification.EXTRA_MESSAGES);
        if (msgs != null && msgs.length > 0 && msgs[msgs.length - 1] instanceof Bundle) {
            CharSequence t = ((Bundle) msgs[msgs.length - 1]).getCharSequence("text");
            if (t != null) return t.toString();
        }
        CharSequence t = x.getCharSequence(Notification.EXTRA_BIG_TEXT);
        if (t == null) t = x.getCharSequence(Notification.EXTRA_TEXT);
        return t == null ? null : t.toString();
    }

    private void check(String sender, String body) {
        ScamCheck.Result r = ScamCheck.check(body);
        String badLink = null;
        if (!r.links.isEmpty()) {
            if (ioc == null) ioc = IocDb.load(this);
            if (phish == null) phish = PhishDb.load(this);
            for (String link : r.links) {
                // Empty key: offline lists only, nothing leaves the phone.
                if (LinkCheck.check(link, ioc, phish, "").danger) { badLink = link; break; }
            }
        }
        if (!r.likelyScam() && badLink == null) return;

        String why = badLink != null ? "It contains a dangerous link (" + badLink + ")."
                : r.reasons.isEmpty() ? "" : r.reasons.get(0);
        String text = why + "\nDon't tap links, call back, pay, or share an OTP or PIN. Tap to see why.";
        Intent open = new Intent(this, MainActivity.class)
                .setAction(Intent.ACTION_SEND).setType("text/plain")
                .putExtra(Intent.EXTRA_TEXT, body)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent tap = PendingIntent.getActivity(this, body.hashCode(), open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Guard.notify(this, body.hashCode(), "⚠ Possible scam from " + sender, text, tap, null);
    }
}
