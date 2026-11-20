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

    /** The running service, so the app can switch the call warning on without a restart. Same process only. */
    static volatile ScamAlertService instance;

    @Override
    public void onListenerConnected() {
        instance = this;
        smsApp = Telephony.Sms.getDefaultSmsPackage(this);
        IntentFilter f = new IntentFilter(Intent.ACTION_PACKAGE_ADDED);
        f.addAction(Intent.ACTION_PACKAGE_REPLACED);
        f.addDataScheme("package");
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(installs, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(installs, f);
        receiverOn = true;
        syncCallWatch();
    }

    @Override
    public void onListenerDisconnected() {
        if (receiverOn) { unregisterReceiver(installs); receiverOn = false; }
        stopCallWatch();
        instance = null;
    }

    // ------------------------------------------------------------------ "on a call" warning

    private final android.os.Handler mainHandler = new android.os.Handler(android.os.Looper.getMainLooper());
    private Object callListener;      // TelephonyCallback (Android 12+) or PhoneStateListener
    private CallGuard call;           // non-null while a call is active
    private long lastEventTime;

    /** Starts or stops listening for calls to match the setting and the phone permission. */
    void syncCallWatch() {
        boolean want = getSharedPreferences(Scanner.PREFS, MODE_PRIVATE).getBoolean(CallGuard.PREF_ON, false)
                && (Build.VERSION.SDK_INT < 31
                    || checkSelfPermission(android.Manifest.permission.READ_PHONE_STATE) == android.content.pm.PackageManager.PERMISSION_GRANTED);
        if (want && callListener == null) startCallWatch();
        else if (!want && callListener != null) stopCallWatch();
    }

    @SuppressWarnings("deprecation")
    private void startCallWatch() {
        android.telephony.TelephonyManager tm = getSystemService(android.telephony.TelephonyManager.class);
        if (tm == null) return;
        try {
            if (Build.VERSION.SDK_INT >= 31) {
                CallCallback cb = new CallCallback(this);
                tm.registerTelephonyCallback(getMainExecutor(), cb);
                callListener = cb;
            } else {
                android.telephony.PhoneStateListener l = new android.telephony.PhoneStateListener() {
                    @Override public void onCallStateChanged(int state, String number) { onCallState(state); }
                };
                tm.listen(l, android.telephony.PhoneStateListener.LISTEN_CALL_STATE);
                callListener = l;
            }
        } catch (SecurityException e) {
            callListener = null; // permission was taken away
        }
    }

    @SuppressWarnings("deprecation")
    private void stopCallWatch() {
        android.telephony.TelephonyManager tm = getSystemService(android.telephony.TelephonyManager.class);
        if (tm != null && callListener != null) {
            if (Build.VERSION.SDK_INT >= 31 && callListener instanceof android.telephony.TelephonyCallback) {
                tm.unregisterTelephonyCallback((android.telephony.TelephonyCallback) callListener);
            } else if (callListener instanceof android.telephony.PhoneStateListener) {
                tm.listen((android.telephony.PhoneStateListener) callListener, android.telephony.PhoneStateListener.LISTEN_NONE);
            }
        }
        callListener = null;
        onCallState(android.telephony.TelephonyManager.CALL_STATE_IDLE);
    }

    @android.annotation.TargetApi(31)
    private static final class CallCallback extends android.telephony.TelephonyCallback
            implements android.telephony.TelephonyCallback.CallStateListener {
        private final ScamAlertService s;
        CallCallback(ScamAlertService s) { this.s = s; }
        @Override public void onCallStateChanged(int state) { s.onCallState(state); }
    }

    /** OFFHOOK = on a call: watch which app comes to the front every 2 seconds until the call ends. */
    private void onCallState(int state) {
        mainHandler.removeCallbacks(poll);
        if (state == android.telephony.TelephonyManager.CALL_STATE_OFFHOOK) {
            if (call == null) { call = CallGuard.newCall(); lastEventTime = System.currentTimeMillis(); }
            mainHandler.postDelayed(poll, 2000);
        } else if (state == android.telephony.TelephonyManager.CALL_STATE_IDLE) {
            call = null;
        }
    }

    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (call == null) return;
            CallGuard g = call;
            long from = lastEventTime, to = System.currentTimeMillis();
            lastEventTime = to;
            worker.execute(() -> checkForeground(g, from, to));
            mainHandler.postDelayed(this, 2000);
        }
    };

    /** Needs Usage access; without it queryEvents returns nothing and no warning is shown. */
    @SuppressWarnings("deprecation")
    private void checkForeground(CallGuard g, long from, long to) {
        try {
            android.app.usage.UsageStatsManager usm = getSystemService(android.app.usage.UsageStatsManager.class);
            android.app.usage.UsageEvents ev = usm.queryEvents(from, to);
            android.app.usage.UsageEvents.Event e = new android.app.usage.UsageEvents.Event();
            while (ev.hasNextEvent()) {
                ev.getNextEvent(e);
                if (e.getEventType() != android.app.usage.UsageEvents.Event.MOVE_TO_FOREGROUND) continue;
                String pkg = e.getPackageName();
                if (!g.shouldWarn(pkg)) continue;
                String label;
                try { label = getPackageManager().getApplicationLabel(getPackageManager().getApplicationInfo(pkg, 0)).toString(); }
                catch (Exception x) { label = pkg; }
                String kind = CallGuard.kind(pkg);
                PendingIntent tap = PendingIntent.getActivity(this, 1930,
                        new Intent(Intent.ACTION_DIAL, android.net.Uri.parse("tel:1930")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
                Guard.notify(this, ("call" + pkg).hashCode(), CallGuard.title(label, kind),
                        CallGuard.text(kind) + "\nTap to dial 1930 (cyber fraud helpline).", tap, null);
            }
        } catch (Exception ignored) { }
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
