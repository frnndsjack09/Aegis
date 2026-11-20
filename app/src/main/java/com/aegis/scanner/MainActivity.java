package com.aegis.scanner;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputType;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.PathInterpolator;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Aegis: an on-phone security and privacy scanner.
 * The whole interface is built in code (no layout files) to keep the project simple.
 */
public class MainActivity extends Activity {

    // ---- colours (set in applyPalette)
    private boolean dark;
    private int cBg, cCard, cText, cSub, cPrimary, cHeaderTop, cHeaderBottom, cLine, cTrack;
    private int cRed, cRedBg, cYellow, cYellowBg, cInfo, cInfoBg, cGreen, cGreenBg;

    /** Sanchar Saathi's Chakshu page for reporting fraud calls, SMS and WhatsApp messages (no public API). */
    private static final String CHAKSHU_URL = "https://sancharsaathi.gov.in/sfc/";

    /** Material "emphasized decelerate" curve: fast start, soft landing. */
    private static final PathInterpolator EASE = new PathInterpolator(0.2f, 0f, 0f, 1f);

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private SharedPreferences prefs;

    // tabs
    private View tabIndicator;
    private final List<TextView> tabLabels = new ArrayList<>();
    private final ScrollView[] pages = new ScrollView[3];
    private int currentTab = -1;
    private Runnable onToolsShown;

    // app-file check (Tools tab)
    private static final int REQ_APK = 41;
    private LinearLayout apkCard;
    private Button apkBtn;
    private TextView apkResult;

    // scan tab state
    private ScoreRing ring;
    private Button scanButton;
    private TextView scanStatus, scanHeadline, scanIntro;
    private LinearLayout summaryRow, resultsBox;
    private final Map<Finding.Level, Section> sections = new EnumMap<>(Finding.Level.class);
    private boolean busy = false;

    /** One group of results ("Act now", "Review", ...) that can fold open and shut. */
    private static class Section {
        View header;
        LinearLayout body;
        TextView chevron;
        boolean open;
    }

    // ------------------------------------------------------------------ lifecycle

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        prefs = getSharedPreferences(Scanner.PREFS, MODE_PRIVATE);
        applyPalette();
        getWindow().setStatusBarColor(cHeaderTop);
        getWindow().setNavigationBarColor(cBg);
        if (!dark) {
            getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        }

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(cBg);
        root.addView(buildHeader());

        FrameLayout content = new FrameLayout(this);
        root.addView(content, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        View[] tabs = {buildScanTab(), buildToolsTab(), buildPrivacyTab()};
        for (int i = 0; i < 3; i++) {
            ScrollView sv = new ScrollView(this);
            sv.setFillViewport(true);
            sv.setClipToPadding(false);
            sv.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
            sv.setVerticalScrollBarEnabled(false);
            sv.addView(tabs[i]);
            sv.setVisibility(View.GONE);
            pages[i] = sv;
            content.addView(sv, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        }
        showTab(0);

        setContentView(root);
        handleIncoming(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIncoming(intent);
    }

    /** "Open with Aegis" or "Share to Aegis" on an .apk file (for example from WhatsApp or Files). */
    @SuppressWarnings("deprecation")
    private void handleIncoming(Intent in) {
        if (in == null) return;
        Uri uri = null;
        if (Intent.ACTION_VIEW.equals(in.getAction())) uri = in.getData();
        else if (Intent.ACTION_SEND.equals(in.getAction())) uri = in.getParcelableExtra(Intent.EXTRA_STREAM);
        if (uri != null) checkApk(uri);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_APK && res == RESULT_OK && data != null && data.getData() != null) checkApk(data.getData());
    }

    private void pickApk() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
                .putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/vnd.android.package-archive", "application/octet-stream"});
        try {
            startActivityForResult(i, REQ_APK);
        } catch (ActivityNotFoundException e) {
            toast("No file picker on this phone");
        }
    }

    private void checkApk(Uri uri) {
        showTab(1);
        pages[1].post(() -> pages[1].smoothScrollTo(0, Math.max(0, offsetTop(apkCard, pages[1].getChildAt(0)) - dp(8))));
        setBusy(apkBtn, true, "Checking…");
        worker.execute(() -> {
            String text;
            int fg, bg;
            try {
                ApkCheck.Facts f = ApkCheck.inspect(this, uri, IocDb.load(this));
                ApkCheck.Verdict v = ApkCheck.judge(f);
                StringBuilder sb = new StringBuilder();
                sb.append(v.level == Finding.Level.RED ? "⚠ " : v.level == Finding.Level.GREEN ? "✓ " : "")
                        .append(v.headline.toUpperCase(Locale.ROOT)).append("\n\n");
                if (!f.label.isEmpty()) {
                    sb.append("App: ").append(f.label);
                    if (!f.version.isEmpty()) sb.append(" ").append(f.version);
                    sb.append("\nApp id: ").append(f.pkg).append('\n');
                }
                if (!f.fileName.isEmpty()) sb.append("File: ").append(f.fileName).append('\n');
                sb.append('\n');
                for (String r : v.reasons) sb.append("• ").append(r).append('\n');
                if (v.level == Finding.Level.RED) {
                    sb.append("\nDelete this file and the message it came with. If you already installed it: turn on "
                            + "Airplane mode, uninstall it, call your bank to block cards and UPI, then call 1930.");
                } else if (v.level == Finding.Level.YELLOW) {
                    sb.append("\nOnly install it if you know exactly who made it. Get apps from the Play Store when you can.");
                } else {
                    sb.append("\nThis only means no warning signs were found. Apps from the Play Store are still safer "
                            + "than files sent by message.");
                }
                text = sb.toString();
                fg = v.level == Finding.Level.RED ? cRed : v.level == Finding.Level.YELLOW ? cYellow : cGreen;
                bg = v.level == Finding.Level.RED ? cRedBg : v.level == Finding.Level.YELLOW ? cYellowBg : cGreenBg;
            } catch (SecurityException e) {
                text = "The app that shared this file didn't let Aegis open it. Tap \"Choose an app file\" and pick it from Downloads instead.";
                fg = cSub;
                bg = alpha(cSub, 0x14);
            } catch (Exception e) {
                text = "Couldn't read this file: " + e.getMessage();
                fg = cSub;
                bg = alpha(cSub, 0x14);
            }
            final String t = text;
            final int f1 = fg, b1 = bg;
            main.post(() -> {
                setBusy(apkBtn, false, "Choose an app file");
                showResult(apkResult, t, f1, b1);
            });
        });
    }

    @Override
    public void onConfigurationChanged(Configuration c) {
        super.onConfigurationChanged(c);
        boolean nowDark = (c.uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        // Colours are baked into the views, so rebuild when the phone switches light/dark.
        if (nowDark != dark && !busy) recreate();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        worker.shutdownNow();
    }

    private void applyPalette() {
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        cHeaderTop = Color.parseColor(dark ? "#17153B" : "#2E2A8C");
        cHeaderBottom = Color.parseColor(dark ? "#221F55" : "#4A44D6");
        cPrimary = Color.parseColor(dark ? "#9796FF" : "#4338CA");
        cBg = Color.parseColor(dark ? "#0B0E1A" : "#F4F6FB");
        cCard = Color.parseColor(dark ? "#141A2C" : "#FFFFFF");
        cText = Color.parseColor(dark ? "#E9ECF5" : "#0F172A");
        cSub = Color.parseColor(dark ? "#9AA3BA" : "#566072");
        cLine = Color.parseColor(dark ? "#222A42" : "#E4E8F0");
        cTrack = Color.parseColor(dark ? "#232A44" : "#ECEEF8");
        cRed = Color.parseColor(dark ? "#F97066" : "#B42318");
        cRedBg = Color.parseColor(dark ? "#3A1614" : "#FEE4E2");
        cYellow = Color.parseColor(dark ? "#FDB022" : "#B54708");
        cYellowBg = Color.parseColor(dark ? "#38290B" : "#FEF0C7");
        cInfo = Color.parseColor(dark ? "#84CAFF" : "#175CD3");
        cInfoBg = Color.parseColor(dark ? "#10284A" : "#D1E9FF");
        cGreen = Color.parseColor(dark ? "#47CD89" : "#067647");
        cGreenBg = Color.parseColor(dark ? "#0C2E1D" : "#DCFAE6");
    }

    private int fg(Finding.Level l) {
        switch (l) {
            case RED: return cRed;
            case YELLOW: return cYellow;
            case INFO: return cInfo;
            default: return cGreen;
        }
    }

    private int bg(Finding.Level l) {
        switch (l) {
            case RED: return cRedBg;
            case YELLOW: return cYellowBg;
            case INFO: return cInfoBg;
            default: return cGreenBg;
        }
    }

    private static String label(Finding.Level l) {
        switch (l) {
            case RED: return "Act now";
            case YELLOW: return "Review";
            case INFO: return "Good to know";
            default: return "All good";
        }
    }

    // ------------------------------------------------------------------ header & tabs

    private View buildHeader() {
        LinearLayout h = new LinearLayout(this);
        h.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{cHeaderTop, cHeaderBottom});
        float r = dp(28);
        g.setCornerRadii(new float[]{0, 0, 0, 0, r, r, r, r});
        h.setBackground(g);
        h.setElevation(dp(4));
        h.setPadding(dp(20), dp(14), dp(20), dp(16));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);

        TextView logo = text("🛡", 22, Color.WHITE, false);
        logo.setGravity(Gravity.CENTER);
        logo.setBackground(round(alpha(Color.WHITE, 0x26), 14));
        top.addView(logo, new LinearLayout.LayoutParams(dp(44), dp(44)));

        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        titles.setPadding(dp(12), 0, dp(8), 0);
        TextView title = text("Aegis", 22, Color.WHITE, false);
        title.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        title.setLetterSpacing(0.01f);
        titles.addView(title);
        titles.addView(text("Phone security & privacy scanner", 13, alpha(Color.WHITE, 0xC8), false));
        top.addView(titles, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView offline = text("● Offline", 11, Color.WHITE, true);
        offline.setBackground(round(alpha(Color.WHITE, 0x22), 12));
        offline.setPadding(dp(10), dp(4), dp(10), dp(4));
        top.addView(offline);
        h.addView(top);

        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(44));
        tlp.topMargin = dp(16);
        h.addView(buildTabBar(), tlp);
        return h;
    }

    /** Segmented control with a white pill that slides to the selected tab. */
    private View buildTabBar() {
        FrameLayout bar = new FrameLayout(this);
        bar.setBackground(round(alpha(Color.WHITE, 0x1F), 22));
        int pad = dp(4);
        bar.setPadding(pad, pad, pad, pad);

        tabIndicator = new View(this);
        tabIndicator.setBackground(round(Color.WHITE, 18));
        tabIndicator.setElevation(dp(2));
        bar.addView(tabIndicator, new FrameLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout labels = new LinearLayout(this);
        labels.setOrientation(LinearLayout.HORIZONTAL);
        String[] names = {"Scan", "Tools", "Privacy"};
        for (int i = 0; i < names.length; i++) {
            final int idx = i;
            TextView t = text(names[i], 15, Color.WHITE, true);
            t.setGravity(Gravity.CENTER);
            t.setOnClickListener(v -> { v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP); showTab(idx); });
            labels.addView(t, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f));
            tabLabels.add(t);
        }
        labels.setElevation(dp(3)); // labels sit above the sliding pill
        bar.addView(labels, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        bar.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, or, ob) -> {
            int w = (r - l - pad * 2) / 3;
            ViewGroup.LayoutParams lp = tabIndicator.getLayoutParams();
            if (lp.width != w) {
                lp.width = w;
                tabIndicator.post(() -> {
                    tabIndicator.setLayoutParams(lp);
                    tabIndicator.setTranslationX(Math.max(0, currentTab) * w);
                });
            }
        });
        return bar;
    }

    private void showTab(int i) {
        if (i == currentTab) {
            pages[i].smoothScrollTo(0, 0); // tapping the current tab jumps back to the top
            return;
        }
        boolean first = currentTab < 0;
        currentTab = i;

        int w = tabIndicator.getLayoutParams().width;
        tabIndicator.animate().cancel();
        if (first || w == 0) tabIndicator.setTranslationX(i * w);
        else tabIndicator.animate().translationX(i * w).setDuration(320).setInterpolator(EASE).start();

        for (int k = 0; k < tabLabels.size(); k++) {
            TextView t = tabLabels.get(k);
            int to = k == i ? cHeaderTop : Color.WHITE;
            if (first) t.setTextColor(to);
            else ObjectAnimator.ofArgb(t, "textColor", t.getCurrentTextColor(), to).setDuration(220).start();
        }

        for (int k = 0; k < pages.length; k++) {
            ScrollView p = pages[k];
            p.animate().cancel();
            if (k == i) {
                p.setVisibility(View.VISIBLE);
                if (first) {
                    p.setAlpha(1f);
                    p.setTranslationY(0);
                } else {
                    p.setAlpha(0f);
                    p.setTranslationY(dp(14));
                    p.animate().alpha(1f).translationY(0).setStartDelay(70).setDuration(280)
                            .setInterpolator(EASE).start();
                }
            } else if (p.getVisibility() == View.VISIBLE) {
                p.animate().alpha(0f).setStartDelay(0).setDuration(110)
                        .withEndAction(() -> p.setVisibility(View.GONE)).start();
            }
        }
        if (i == 1 && onToolsShown != null) onToolsShown.run();
    }

    // ------------------------------------------------------------------ SCAN tab

    private View buildScanTab() {
        LinearLayout page = page();

        LinearLayout hero = card();
        hero.setGravity(Gravity.CENTER_HORIZONTAL);
        hero.setPadding(dp(20), dp(22), dp(20), dp(18));

        ring = new ScoreRing(this, cTrack, cPrimary, cText, cSub);
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(dp(148), dp(148));
        rlp.bottomMargin = dp(14);
        hero.addView(ring, rlp);

        scanHeadline = text("Ready to scan", 21, cText, false);
        scanHeadline.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        scanHeadline.setGravity(Gravity.CENTER);
        hero.addView(scanHeadline, wrapCenter());

        scanStatus = text("", 13, cSub, false);
        scanStatus.setGravity(Gravity.CENTER);
        scanStatus.setPadding(0, dp(4), 0, 0);
        scanStatus.setVisibility(View.GONE);
        hero.addView(scanStatus, wrapCenter());

        scanIntro = text("Checks every app for known spy apps and suspicious behaviour, looks for hidden "
                + "access and traffic interception, and reviews your phone's security settings. Nothing leaves "
                + "your phone.", 14, cSub, false);
        scanIntro.setGravity(Gravity.CENTER);
        scanIntro.setLineSpacing(0, 1.2f);
        scanIntro.setPadding(dp(4), dp(10), dp(4), dp(6));
        hero.addView(scanIntro);

        summaryRow = new LinearLayout(this);
        summaryRow.setOrientation(LinearLayout.HORIZONTAL);
        summaryRow.setVisibility(View.GONE);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.topMargin = dp(14);
        hero.addView(summaryRow, slp);

        scanButton = primaryButton("Scan my phone");
        ((LinearLayout.LayoutParams) scanButton.getLayoutParams()).topMargin = dp(16);
        scanButton.setOnClickListener(v -> startScan());
        hero.addView(scanButton);
        page.addView(hero);

        resultsBox = new LinearLayout(this);
        resultsBox.setOrientation(LinearLayout.VERTICAL);
        page.addView(resultsBox);

        long last = prefs.getLong("snap_time", 0);
        if (last > 0) {
            scanStatus.setVisibility(View.VISIBLE);
            scanStatus.setText("Last scan: " + fmtTime(last));
        }
        return page;
    }

    private void startScan() {
        if (busy) return;
        busy = true;
        setBusy(scanButton, true, "Scanning…");
        ring.setScanning(cPrimary);
        scanHeadline.setText("Scanning your phone");
        scanHeadline.setTextColor(cText);
        scanStatus.setVisibility(View.VISIBLE);
        scanStatus.setText("Starting…");
        hide(scanIntro);
        hide(summaryRow);
        resultsBox.animate().cancel();
        resultsBox.animate().alpha(0f).setDuration(150).withEndAction(() -> {
            resultsBox.removeAllViews();
            resultsBox.setAlpha(1f);
        }).start();

        worker.execute(() -> {
            List<Finding> results;
            String error = null;
            Scanner s = null;
            try {
                IocDb ioc = IocDb.load(this);
                s = new Scanner(this, ioc);
                results = s.run((msg, pct) -> main.post(() -> {
                    scanStatus.setText(msg);
                    ring.setPercent(pct);
                }));
            } catch (Throwable t) {
                results = new ArrayList<>();
                error = t.toString();
            }
            final List<Finding> fr = results;
            final String err = error;
            final Scanner fs = s;
            main.post(() -> {
                busy = false;
                setBusy(scanButton, false, "Scan again");
                if (err != null) {
                    ring.setResult(cRed, "!", "error");
                    scanHeadline.setText("Scan failed");
                    scanHeadline.setTextColor(cRed);
                    scanStatus.setText(err);
                    return;
                }
                // Results replace the old ones once the fade-out above has finished.
                resultsBox.postDelayed(() -> showResults(fr, fs), 160);
            });
        });
    }

    private void showResults(List<Finding> list, Scanner s) {
        resultsBox.animate().cancel();
        resultsBox.setAlpha(1f);
        resultsBox.removeAllViews();
        sections.clear();

        Map<Finding.Level, Integer> counts = new EnumMap<>(Finding.Level.class);
        for (Finding.Level l : Finding.Level.values()) counts.put(l, 0);
        for (Finding f : list) counts.put(f.level, counts.get(f.level) + 1);
        int red = counts.get(Finding.Level.RED), yellow = counts.get(Finding.Level.YELLOW);

        if (red > 0) {
            ring.setResult(cRed, String.valueOf(red), red == 1 ? "problem" : "problems");
            scanHeadline.setText(red + (red == 1 ? " problem needs" : " problems need") + " attention");
            scanHeadline.setTextColor(cRed);
        } else if (yellow > 0) {
            ring.setResult(cYellow, String.valueOf(yellow), "to review");
            scanHeadline.setText("No serious problems");
            scanHeadline.setTextColor(cYellow);
        } else {
            ring.setResult(cGreen, "✓", "clean");
            scanHeadline.setText("Your phone looks clean");
            scanHeadline.setTextColor(cGreen);
        }
        scanStatus.setText("Scanned " + s.appsScanned + " apps (" + s.userApps + " you installed) · "
                + fmtTime(System.currentTimeMillis()));
        ring.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS);

        buildSummary(counts);

        int order = 0;
        for (Finding f : list) {
            Section sec = sections.get(f.level);
            if (sec == null) {
                sec = newSection(f.level, counts.get(f.level));
                resultsBox.addView(sec.header);
                resultsBox.addView(sec.body);
                enter(sec.header, order++);
            }
            View card = findingCard(f);
            sec.body.addView(card);
            if (sec.open) enter(card, order++);
        }

        TextView note = text("A clean result means no KNOWN spy app or warning sign was found. Very advanced "
                + "spyware can still hide. If you're worried about a specific person, see the Privacy tab → Get help.",
                12, cSub, false);
        note.setLineSpacing(0, 1.2f);
        note.setPadding(dp(8), dp(14), dp(8), dp(28));
        resultsBox.addView(note);
        enter(note, order);
    }

    /** Four tappable counters under the ring; tapping jumps to that group. */
    private void buildSummary(Map<Finding.Level, Integer> counts) {
        summaryRow.removeAllViews();
        for (Finding.Level l : Finding.Level.values()) {
            int n = counts.get(l);
            LinearLayout chip = new LinearLayout(this);
            chip.setOrientation(LinearLayout.VERTICAL);
            chip.setGravity(Gravity.CENTER);
            chip.setPadding(dp(4), dp(10), dp(4), dp(10));
            int fgc = n > 0 ? fg(l) : cSub;
            chip.setBackground(ripple(n > 0 ? bg(l) : alpha(cSub, 0x12), fgc, 14));
            TextView num = text(String.valueOf(n), 20, fgc, false);
            num.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
            TextView lab = text(label(l), 11, fgc, true);
            lab.setSingleLine(true);
            lab.setEllipsize(TextUtils.TruncateAt.END);
            chip.addView(num);
            chip.addView(lab);
            if (n > 0) chip.setOnClickListener(v -> jumpToSection(l));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            lp.setMargins(dp(3), 0, dp(3), 0);
            summaryRow.addView(chip, lp);
        }
        show(summaryRow);
    }

    private void jumpToSection(Finding.Level l) {
        Section s = sections.get(l);
        if (s == null) return;
        if (!s.open) toggle(s);
        s.header.post(() -> pages[0].smoothScrollTo(0, offsetTop(s.header, pages[0].getChildAt(0)) - dp(8)));
    }

    private Section newSection(Finding.Level level, int count) {
        Section s = new Section();
        // "All good" is folded away by default so problems stay at the top.
        s.open = level != Finding.Level.GREEN;

        LinearLayout h = new LinearLayout(this);
        h.setOrientation(LinearLayout.HORIZONTAL);
        h.setGravity(Gravity.CENTER_VERTICAL);
        h.setPadding(dp(8), dp(12), dp(8), dp(12));
        h.setBackground(ripple(Color.TRANSPARENT, fg(level), 12));
        LinearLayout.LayoutParams hlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        hlp.topMargin = dp(10);
        h.setLayoutParams(hlp);

        View dot = new View(this);
        dot.setBackground(round(fg(level), 5));
        h.addView(dot, new LinearLayout.LayoutParams(dp(10), dp(10)));

        TextView t = text(label(level).toUpperCase(Locale.ROOT), 12, fg(level), true);
        t.setLetterSpacing(0.1f);
        t.setPadding(dp(10), 0, dp(8), 0);
        h.addView(t);

        TextView badge = text(String.valueOf(count), 11, fg(level), true);
        badge.setBackground(round(bg(level), 10));
        badge.setPadding(dp(8), dp(1), dp(8), dp(1));
        h.addView(badge);

        View spacer = new View(this);
        h.addView(spacer, new LinearLayout.LayoutParams(0, 1, 1f));

        s.chevron = text("⌄", 18, cSub, true);
        s.chevron.setGravity(Gravity.CENTER);
        s.chevron.setRotation(s.open ? 0f : -90f);
        h.addView(s.chevron, new LinearLayout.LayoutParams(dp(28), dp(24)));
        h.setOnClickListener(v -> toggle(s));
        s.header = h;

        s.body = new LinearLayout(this);
        s.body.setOrientation(LinearLayout.VERTICAL);
        s.body.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        if (!s.open) s.body.setVisibility(View.GONE);
        sections.put(level, s);
        return s;
    }

    private void toggle(Section s) {
        s.open = !s.open;
        s.chevron.animate().rotation(s.open ? 0f : -90f).setDuration(220).setInterpolator(EASE).start();
        if (s.open) expand(s.body);
        else collapse(s.body, null);
    }

    private View findingCard(Finding f) {
        int fgc = fg(f.level), bgc = bg(f.level);

        LinearLayout outer = card();
        outer.setOrientation(LinearLayout.HORIZONTAL);
        outer.setPadding(0, 0, 0, 0);
        outer.setClipToOutline(true);

        View stripe = new View(this);
        stripe.setBackgroundColor(fgc);
        outer.addView(stripe, new LinearLayout.LayoutParams(dp(4), ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setPadding(dp(14), dp(14), dp(16), dp(14));
        outer.addView(c, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView pill = text(f.category.toUpperCase(Locale.ROOT), 10, fgc, true);
        pill.setLetterSpacing(0.06f);
        pill.setBackground(round(bgc, 10));
        pill.setPadding(dp(8), dp(3), dp(8), dp(3));
        c.addView(pill, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = text(f.title, 16, cText, true);
        title.setPadding(0, dp(9), 0, dp(4));
        c.addView(title);

        TextView detail = text(f.detail, 14, cSub, false);
        detail.setLineSpacing(0, 1.2f);
        c.addView(detail);

        if (!f.actions.isEmpty()) {
            HorizontalScrollView hs = new HorizontalScrollView(this);
            hs.setHorizontalScrollBarEnabled(false);
            hs.setOverScrollMode(View.OVER_SCROLL_NEVER);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(0, dp(10), 0, 0);
            for (Finding.Action a : f.actions) {
                Button b = smallButton(a.label, a.type == Finding.ActionType.UNINSTALL ? cRed : cPrimary);
                b.setOnClickListener(v -> runAction(a, outer));
                row.addView(b);
            }
            hs.addView(row);
            c.addView(hs);
        }
        return outer;
    }

    private void runAction(Finding.Action a, View card) {
        switch (a.type) {
            case APP_INFO:
                launch(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.fromParts("package", a.target, null)));
                break;
            case UNINSTALL:
                launch(new Intent(Intent.ACTION_DELETE, Uri.fromParts("package", a.target, null)));
                break;
            case OPEN_SETTINGS:
                launch(new Intent(a.target));
                break;
            case OPEN_URL:
                launch(new Intent(Intent.ACTION_VIEW, Uri.parse(a.target)));
                break;
            case DIAL:
                launch(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + Uri.encode(a.target))));
                break;
            case TRUST_APP:
                Set<String> t = new HashSet<>(prefs.getStringSet("trusted", new HashSet<>()));
                t.add(a.target);
                prefs.edit().putStringSet("trusted", t).apply();
                collapse(card, null);
                toast("Marked as trusted. It won't be flagged again (undo in Tools).");
                break;
        }
    }

    private void launch(Intent i) {
        try {
            startActivity(i);
        } catch (ActivityNotFoundException | SecurityException e) {
            try {
                startActivity(new Intent(Settings.ACTION_SETTINGS));
                toast("This phone has no direct shortcut. Opened Settings instead.");
            } catch (Exception ignored) { }
        }
    }

    // ------------------------------------------------------------------ TOOLS tab

    private View buildToolsTab() {
        LinearLayout page = page();

        // --- App file check (before installing)
        apkCard = card();
        apkCard.addView(cardHeader("📦", "Check an app file before installing", cRed, cRedBg));
        apkCard.addView(cardText("Got a \"wedding invitation\", \"RTO challan\", \"reward points\" or bank app as an .apk "
                + "file on WhatsApp? Check it here first. Aegis reads the file without installing it. You can also "
                + "tap the file in WhatsApp or Files and choose \"Open with Aegis\"."));
        apkResult = resultBox();
        apkBtn = primaryButton("Choose an app file");
        apkBtn.setOnClickListener(v -> pickApk());
        apkCard.addView(apkBtn);
        apkCard.addView(apkResult);
        page.addView(apkCard);

        // --- Trackers
        LinearLayout tr = card();
        tr.addView(cardHeader("🕵", "Trackers inside your apps", cInfo, cInfoBg));
        tr.addView(cardText("Finds advertising and analytics code (Facebook, Google, AppsFlyer…) built into each app "
                + "you installed. \"Contains\" means the code is there; it doesn't prove it's active. "
                + "To actually block trackers, install the free app TrackerControl."));
        ProgressBar trBar = thinProgress();
        TextView trStatus = statusText();
        TextView trResult = resultBox();
        Button trBtn = primaryButton("Scan apps for trackers");
        LinearLayout trResults = new LinearLayout(this);
        trResults.setOrientation(LinearLayout.VERTICAL);
        trBtn.setOnClickListener(v -> runTrackerScan(trBtn, trBar, trStatus, trResult, trResults));
        tr.addView(trBtn);
        tr.addView(trBar);
        tr.addView(trStatus);
        tr.addView(trResult);
        tr.addView(trResults);
        page.addView(tr);

        // --- Password leak
        LinearLayout pw = card();
        pw.addView(cardHeader("🔑", "Has my password leaked?", cYellow, cYellowBg));
        pw.addView(cardText("Checks the Have I Been Pwned database of leaked passwords. Your password never leaves "
                + "the phone: only the first 5 characters of a scrambled (hashed) version are sent."));
        EditText pwInput = input("Type a password to check", true);
        pw.addView(pwInput);
        TextView pwResult = resultBox();
        Button pwBtn = primaryButton("Check password");
        pwBtn.setOnClickListener(v -> {
            String p = pwInput.getText().toString();
            if (p.isEmpty()) { shake(pwInput); toast("Type a password first"); return; }
            setBusy(pwBtn, true, "Checking…");
            worker.execute(() -> {
                String msg;
                int color, bgc;
                try {
                    int n = Net.pwnedPasswordCount(p);
                    if (n > 0) {
                        msg = "⚠ LEAKED. This password appears " + String.format(Locale.US, "%,d", n)
                                + " times in data breaches. Stop using it everywhere and change it now.";
                        color = cRed;
                        bgc = cRedBg;
                    } else {
                        msg = "✓ Not found in known leaks. Still use a different password for every account.";
                        color = cGreen;
                        bgc = cGreenBg;
                    }
                } catch (Exception e) {
                    msg = "Couldn't check (no internet?): " + e.getMessage();
                    color = cSub;
                    bgc = alpha(cSub, 0x14);
                }
                final String m = msg;
                final int col = color, b = bgc;
                main.post(() -> {
                    setBusy(pwBtn, false, "Check password");
                    showResult(pwResult, m, col, b);
                    pwInput.setText("");
                });
            });
        });
        pw.addView(pwBtn);
        pw.addView(pwResult);
        pw.addView(linkText("Check if your EMAIL was in a breach → haveibeenpwned.com", "https://haveibeenpwned.com"));
        page.addView(pw);

        // --- Scam message checker
        LinearLayout sm = card();
        sm.addView(cardHeader("💬", "Is this message a scam?", cRed, cRedBg));
        sm.addView(cardText("Paste an SMS, WhatsApp or email message. Checks for fake KYC, OTP and UPI-PIN requests, "
                + "'digital arrest' and parcel threats, prize and job offers, and checks every link inside it. "
                + "Nothing is sent anywhere."));
        EditText smInput = input("Paste the message here", false);
        smInput.setSingleLine(false);
        smInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        smInput.setMinLines(3);
        smInput.setMaxLines(8);
        smInput.setGravity(Gravity.TOP | Gravity.START);
        sm.addView(smInput);
        TextView smResult = resultBox();
        LinearLayout smActions = new LinearLayout(this);
        smActions.setVisibility(View.GONE);
        Button chakshu = smallButton("Report to Chakshu", cPrimary);
        chakshu.setOnClickListener(v -> launch(new Intent(Intent.ACTION_VIEW, Uri.parse(CHAKSHU_URL))));
        Button call1930 = smallButton("Lost money? Call 1930", cRed);
        call1930.setOnClickListener(v -> launch(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930"))));
        smActions.addView(chakshu);
        smActions.addView(call1930);
        Button smBtn = primaryButton("Check message");
        smBtn.setOnClickListener(v -> {
            String msg = smInput.getText().toString().trim();
            if (msg.isEmpty()) { shake(smInput); toast("Paste a message first"); return; }
            setBusy(smBtn, true, "Checking…");
            worker.execute(() -> {
                ScamCheck.Result r = ScamCheck.check(msg);
                IocDb ioc = IocDb.load(this);
                Set<String> phish = PhishDb.load(this);
                boolean badLink = false, warnLink = false;
                StringBuilder sb = new StringBuilder();
                for (String reason : r.reasons) sb.append("• ").append(reason).append('\n');
                for (String link : r.links) {
                    LinkCheck.Result lr = LinkCheck.check(link, ioc, phish, "");
                    badLink |= lr.danger;
                    warnLink |= lr.warnings;
                    sb.append("\nLink: ").append(link).append('\n').append(lr.text.trim()).append('\n');
                }
                boolean danger = r.likelyScam() || badLink;
                boolean careful = danger || r.score > 0 || warnLink;
                String head = danger ? "⚠ LIKELY A SCAM. Don't reply, call back, pay or open links.\n\n"
                        : careful ? "Be careful with this message.\n\n"
                        : "✓ No common scam signs found. Still never share an OTP or PIN.\n";
                String text = head + sb.toString().trim()
                        + (careful ? "\n\nReport it on Sanchar Saathi (Chakshu) so the number can be blocked. "
                        + "If you already paid, call 1930 straight away." : "");
                main.post(() -> {
                    setBusy(smBtn, false, "Check message");
                    if (danger) showResult(smResult, text, cRed, cRedBg);
                    else if (careful) showResult(smResult, text, cYellow, cYellowBg);
                    else showResult(smResult, text, cGreen, cGreenBg);
                    smActions.setVisibility(careful ? View.VISIBLE : View.GONE);
                });
            });
        });
        sm.addView(smBtn);
        sm.addView(smResult);
        sm.addView(smActions);
        page.addView(sm);

        // --- Link checker
        LinearLayout lk = card();
        lk.addView(cardHeader("🔗", "Is this link safe?", cPrimary, alpha(cPrimary, 0x22)));
        lk.addView(cardText("Paste a link from an SMS, WhatsApp or email before opening it. Checks for fake-bank "
                + "tricks, hidden destinations, known spy-app and government-spyware sites, and "
                + PhishDb.SOURCES.length + " offline phishing blocklists" + (abuseKey().isEmpty()
                ? ". Add a free abuse.ch key below to also check the URLhaus malware database." : ", plus the URLhaus malware database.")));
        EditText lkInput = input("https://…", false);
        lk.addView(lkInput);
        TextView lkResult = resultBox();
        Button lkBtn = primaryButton("Check link");
        lkBtn.setOnClickListener(v -> {
            String url = lkInput.getText().toString().trim();
            if (url.isEmpty()) { shake(lkInput); toast("Paste a link first"); return; }
            setBusy(lkBtn, true, "Checking…");
            worker.execute(() -> {
                LinkCheck.Result r = LinkCheck.check(url, IocDb.load(this), PhishDb.load(this), abuseKey());
                main.post(() -> {
                    setBusy(lkBtn, false, "Check link");
                    if (r.danger) showResult(lkResult, r.text, cRed, cRedBg);
                    else if (r.warnings) showResult(lkResult, r.text, cYellow, cYellowBg);
                    else showResult(lkResult, r.text, cGreen, cGreenBg);
                });
            });
        });
        lk.addView(lkBtn);
        lk.addView(lkResult);
        page.addView(lk);

        // --- MalwareBazaar
        LinearLayout mb = card();
        mb.addView(cardHeader("🦠", "Malware database check", cRed, cRedBg));
        mb.addView(cardText("Compares a fingerprint of every app you installed with MalwareBazaar's database of over "
                + "a million malware files. Needs a free abuse.ch key (sign up at auth.abuse.ch, then paste it here). "
                + "Only fingerprints are sent, never your files."));
        LinearLayout keyRow = new LinearLayout(this);
        keyRow.setOrientation(LinearLayout.HORIZONTAL);
        keyRow.setGravity(Gravity.CENTER_VERTICAL);
        EditText keyInput = input("abuse.ch Auth-Key", false);
        keyInput.setText(abuseKey());
        LinearLayout.LayoutParams klp = (LinearLayout.LayoutParams) keyInput.getLayoutParams();
        klp.width = 0;
        klp.weight = 1f;
        klp.rightMargin = dp(8);
        keyRow.addView(keyInput, klp);
        Button saveKey = smallButton("Save key", cPrimary);
        saveKey.setOnClickListener(v -> {
            prefs.edit().putString("abuse_key", keyInput.getText().toString().trim()).apply();
            keyInput.clearFocus();
            toast("Key saved on this phone");
        });
        keyRow.addView(saveKey);
        mb.addView(keyRow);
        ProgressBar mbBar = thinProgress();
        TextView mbStatus = statusText();
        TextView mbResult = resultBox();
        Button mbBtn = primaryButton("Check all my apps");
        mbBtn.setOnClickListener(v -> runMalwareBazaar(mbBtn, mbBar, mbStatus, mbResult));
        mb.addView(mbBtn);
        mb.addView(mbBar);
        mb.addView(mbStatus);
        mb.addView(mbResult);
        mb.addView(linkText("Get a free key → auth.abuse.ch", "https://auth.abuse.ch/"));
        page.addView(mb);

        // --- Shizuku deep check
        LinearLayout sz = card();
        sz.addView(cardHeader("🎙", "Who really used my mic, camera & location?", cInfo, cInfoBg));
        sz.addView(cardText("Normal apps can't see this. With the free app Shizuku (started once with Wireless "
                + "debugging, no root), Aegis can read Android's own record of when each app last used the "
                + "microphone, camera, location, SMS, contacts or clipboard. Read-only. Turn Wireless debugging "
                + "off again afterwards."));
        ProgressBar szBar = thinProgress();
        TextView szResult = resultBox();
        Button szBtn = primaryButton("Check real usage");
        szBtn.setOnClickListener(v -> runShizuku(szBtn, szBar, szResult));
        sz.addView(szBtn);
        sz.addView(szBar);
        sz.addView(szResult);
        sz.addView(linkText("Get Shizuku → shizuku.rikka.app", "https://shizuku.rikka.app/"));
        page.addView(sz);

        // --- Updates
        LinearLayout up = card();
        up.addView(cardHeader("⟳", "Update detection databases", cGreen, cGreenBg));
        TextView upStatus = cardText(dbStatus());
        TextView upResult = resultBox();
        Button upBtn = primaryButton("Download latest");
        upBtn.setOnClickListener(v -> runUpdate(upBtn, upStatus, upResult));
        up.addView(upStatus);
        up.addView(upBtn);
        up.addView(upResult);
        page.addView(up);

        // --- Trusted apps
        LinearLayout ta = card();
        ta.addView(cardHeader("✓", "Apps you marked as trusted", cPrimary, alpha(cPrimary, 0x22)));
        LinearLayout taList = new LinearLayout(this);
        taList.setOrientation(LinearLayout.VERTICAL);
        Button taClear = smallButton("Clear list", cRed);
        Runnable[] refresh = new Runnable[1];
        refresh[0] = () -> {
            taList.removeAllViews();
            Set<String> t = prefs.getStringSet("trusted", new HashSet<>());
            taClear.setVisibility(t.isEmpty() ? View.GONE : View.VISIBLE);
            if (t.isEmpty()) {
                taList.addView(cardText("None yet. Tap \"I trust this app\" on a scan result to hide it from future scans."));
                return;
            }
            for (String pkg : new TreeSet<>(t)) {
                LinearLayout row = new LinearLayout(this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setPadding(0, dp(4), 0, dp(4));
                TextView name = text(pkg, 13, cText, false);
                name.setSingleLine(true);
                name.setEllipsize(TextUtils.TruncateAt.MIDDLE);
                row.addView(name, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
                Button rm = smallButton("Remove", cSub);
                rm.setOnClickListener(v -> {
                    Set<String> cur = new HashSet<>(prefs.getStringSet("trusted", new HashSet<>()));
                    cur.remove(pkg);
                    prefs.edit().putStringSet("trusted", cur).apply();
                    collapse(row, refresh[0]);
                });
                row.addView(rm);
                taList.addView(row);
            }
        };
        refresh[0].run();
        onToolsShown = refresh[0];
        taClear.setOnClickListener(v -> {
            prefs.edit().remove("trusted").apply();
            refresh[0].run();
            toast("Trusted list cleared. Scan again to re-check those apps.");
        });
        ta.addView(taList);
        ta.addView(taClear);
        page.addView(ta);

        return page;
    }

    private String abuseKey() {
        return prefs.getString("abuse_key", "");
    }

    private void runTrackerScan(Button btn, ProgressBar bar, TextView status, TextView result, LinearLayout out) {
        if (busy) { toast("Wait for the current task to finish"); return; }
        busy = true;
        setBusy(btn, true, "Scanning…");
        hide(result);
        out.removeAllViews();
        bar.setProgress(0);
        show(bar);
        show(status);
        worker.execute(() -> {
            TrackerDb db = TrackerDb.load(this);
            List<Scanner.App> apps = Scanner.userApps(this);
            List<String[]> rows = new ArrayList<>();
            int withTrackers = 0, total = 0;
            for (int i = 0; i < apps.size(); i++) {
                Scanner.App a = apps.get(i);
                final int n = i + 1;
                main.post(() -> {
                    status.setText("Scanning " + n + "/" + apps.size() + ": " + a.label);
                    bar.setProgress(n * 100 / Math.max(1, apps.size()));
                });
                TreeSet<String> found = db.scanApk(a.apk);
                if (!found.isEmpty()) {
                    withTrackers++;
                    total += found.size();
                    rows.add(new String[]{a.label, found.size() + "", String.join(", ", found), a.pkg});
                }
            }
            rows.sort((x, y) -> Integer.parseInt(y[1]) - Integer.parseInt(x[1]));
            final int wt = withTrackers, tt = total;
            main.post(() -> {
                busy = false;
                setBusy(btn, false, "Scan again");
                hide(bar);
                hide(status);
                showResult(result, wt + " of " + apps.size() + " apps contain trackers (" + tt + " in total). "
                        + (db.fromExodus ? "Using the Exodus Privacy list (" + db.size() + " signatures)."
                        : "Using a small built-in list; the Exodus list couldn't be read. Tap \"Download latest\" below."),
                        wt > 0 ? cInfo : cGreen, wt > 0 ? cInfoBg : cGreenBg);
                int order = 0;
                for (String[] r : rows) {
                    View item = trackerRow(r);
                    out.addView(item);
                    enter(item, order++);
                }
            });
        });
    }

    /** One app in the tracker list: name, tracker names, count badge. Tap opens App info. */
    private View trackerRow(String[] r) {
        LinearLayout item = new LinearLayout(this);
        item.setOrientation(LinearLayout.HORIZONTAL);
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setPadding(dp(12), dp(10), dp(10), dp(10));
        item.setBackground(ripple(alpha(cInfo, 0x0E), cInfo, 12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(6);
        item.setLayoutParams(lp);

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        TextView name = text(r[0], 15, cText, true);
        name.setSingleLine(true);
        name.setEllipsize(TextUtils.TruncateAt.END);
        TextView list = text(r[2], 12, cSub, false);
        list.setLineSpacing(0, 1.15f);
        list.setPadding(0, dp(2), 0, 0);
        col.addView(name);
        col.addView(list);
        item.addView(col, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView badge = text(r[1], 12, cInfo, true);
        badge.setGravity(Gravity.CENTER);
        badge.setBackground(round(cInfoBg, 12));
        badge.setMinWidth(dp(28));
        badge.setPadding(dp(8), dp(3), dp(8), dp(3));
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        blp.leftMargin = dp(10);
        item.addView(badge, blp);

        TextView arrow = text("›", 20, cSub, false);
        arrow.setPadding(dp(8), 0, 0, 0);
        item.addView(arrow);

        item.setOnClickListener(v -> launch(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", r[3], null))));
        return item;
    }

    private void runMalwareBazaar(Button btn, ProgressBar bar, TextView status, TextView result) {
        String key = abuseKey();
        if (key.isEmpty()) { toast("Paste your abuse.ch key and tap Save key first"); return; }
        if (busy) { toast("Wait for the current task to finish"); return; }
        busy = true;
        setBusy(btn, true, "Checking…");
        hide(result);
        bar.setProgress(0);
        show(bar);
        show(status);
        worker.execute(() -> {
            SharedPreferences cache = getSharedPreferences("hash_cache", MODE_PRIVATE);
            SharedPreferences.Editor ed = cache.edit();
            List<Scanner.App> apps = Scanner.userApps(this);
            List<String> hits = new ArrayList<>();
            String error = null;
            int checked = 0;
            for (int i = 0; i < apps.size(); i++) {
                Scanner.App a = apps.get(i);
                final int n = i + 1;
                main.post(() -> {
                    status.setText("Checking " + n + "/" + apps.size() + ": " + a.label);
                    bar.setProgress(n * 100 / Math.max(1, apps.size()));
                });
                String h = Scanner.apkSha256Cached(a, cache, ed);
                if (h == null) continue;
                try {
                    String sig = Net.malwareBazaar(h, key);
                    checked++;
                    if (sig != null) hits.add(a.label + " (" + a.pkg + "): " + sig);
                } catch (Exception e) {
                    error = e.getMessage();
                    break;
                }
            }
            ed.apply();
            final String err = error;
            final int c = checked;
            main.post(() -> {
                busy = false;
                setBusy(btn, false, "Check all my apps");
                hide(bar);
                hide(status);
                if (!hits.isEmpty()) {
                    showResult(result, "⚠ Known malware found:\n• " + String.join("\n• ", hits)
                            + "\n\nUninstall these apps (Settings → Apps).", cRed, cRedBg);
                } else if (err != null) {
                    showResult(result, "Stopped after " + c + " apps: " + err, cSub, alpha(cSub, 0x14));
                } else {
                    showResult(result, "✓ Checked " + c + " apps. None are known malware files.", cGreen, cGreenBg);
                }
            });
        });
    }

    private void runUpdate(Button btn, TextView status, TextView result) {
        if (busy) { toast("Wait for the current task to finish"); return; }
        busy = true;
        setBusy(btn, true, "Downloading…");
        hide(result);
        worker.execute(() -> {
            StringBuilder log = new StringBuilder();
            boolean ok = true;
            try {
                Net.download(this, IocDb.IOC_URL, "ioc.yaml");
                Net.download(this, IocDb.SAMPLES_URL, "samples.csv");
                IocDb test = IocDb.load(this);
                if (test.packages.size() < 100) {
                    new File(getFilesDir(), "ioc.yaml").delete();
                    new File(getFilesDir(), "samples.csv").delete();
                    log.append("Spy-app list download looked wrong; kept the built-in copy.\n");
                    ok = false;
                } else {
                    log.append("✓ Spy-app list updated.\n");
                }
            } catch (Exception e) {
                log.append("Spy-app list: ").append(e.getMessage()).append('\n');
                ok = false;
            }
            try {
                for (String f : IocDb.ANDRODR_FILES) Net.download(this, IocDb.ANDRODR_BASE + f, "androdr_" + f);
                log.append("✓ AndroDR malware list updated.\n");
            } catch (Exception e) {
                for (String f : IocDb.ANDRODR_FILES) new File(getFilesDir(), "androdr_" + f).delete();
                log.append("AndroDR list: ").append(e.getMessage()).append(" (kept the built-in copy)\n");
                ok = false;
            }
            try {
                int rows = updateMvt();
                log.append("✓ Government-spyware list updated (").append(rows).append(" indicators).\n");
            } catch (Exception e) {
                log.append("Government-spyware list: ").append(e.getMessage()).append(" (kept the old copy)\n");
                ok = false;
            }
            for (String[] s : PhishDb.SOURCES) {
                try {
                    Net.download(this, s[1], s[0] + ".new");
                    File nf = new File(getFilesDir(), s[0] + ".new");
                    int n = PhishDb.countDomains(nf);
                    if (n < 1000 || !nf.renameTo(new File(getFilesDir(), s[0]))) {
                        nf.delete();
                        throw new Exception("download looked wrong");
                    }
                    log.append("✓ Phishing list updated (").append(String.format(Locale.US, "%,d", n)).append(" sites).\n");
                } catch (Exception e) {
                    log.append("Phishing list (").append(Uri.parse(s[1]).getHost()).append("): ")
                            .append(e.getMessage()).append('\n');
                    ok = false;
                }
            }
            try {
                Net.download(this, TrackerDb.TRACKERS_URL, TrackerDb.FILE_NAME);
                TrackerDb t = TrackerDb.load(this);
                if (!t.fromExodus) {
                    new File(getFilesDir(), TrackerDb.FILE_NAME).delete();
                    log.append("Tracker list download looked wrong; kept the built-in list.\n");
                    ok = false;
                } else {
                    log.append("✓ Tracker list updated (").append(t.size()).append(" signatures).\n");
                }
            } catch (Exception e) {
                log.append("Tracker list: ").append(e.getMessage()).append('\n');
                ok = false;
            }
            prefs.edit().putLong("db_time", System.currentTimeMillis()).apply();
            final boolean good = ok;
            main.post(() -> {
                busy = false;
                setBusy(btn, false, "Download latest");
                status.setText(dbStatus());
                showResult(result, log.toString().trim(), good ? cGreen : cYellow, good ? cGreenBg : cYellowBg);
            });
        });
    }

    /**
     * Downloads MVT's list of indicator files (Pegasus, Predator, …) and converts the parts a phone
     * can check into mvt_iocs.tsv. Skips the stalkerware file, which duplicates AssoEchap's list.
     */
    private int updateMvt() throws Exception {
        String index = Net.get(IocDb.MVT_INDEX_URL, null, null);
        StringBuilder out = new StringBuilder("# Converted from mvt-project/mvt-indicators\n");
        String name = null, owner = null, repo = null, branch = null;
        int files = 0;
        for (String line : index.split("\n")) {
            String t = line.trim();
            if (t.equals("-")) { name = owner = repo = branch = null; continue; }
            int c = t.indexOf(':');
            if (c < 0) continue;
            String k = t.substring(0, c).trim(), v = t.substring(c + 1).trim();
            switch (k) {
                case "name": name = v.replace(" Indicators of Compromise", ""); break;
                case "owner": owner = v; break;
                case "repo": repo = v; break;
                case "branch": branch = v; break;
                case "path":
                    if (owner == null || repo == null || repo.equals("stalkerware-indicators")) break;
                    String url = "https://raw.githubusercontent.com/" + owner + "/" + repo + "/"
                            + (branch == null ? "main" : branch) + "/" + v;
                    IocDb.stixToTsv(Net.get(url, null, null), name == null ? v : name, out);
                    files++;
                    break;
            }
        }
        int rows = out.length() == 0 ? 0 : out.toString().split("\n").length - 1;
        if (files < 5 || rows < 1000) throw new Exception("download looked wrong");
        Net.save(this, IocDb.MVT_FILE, out.toString());
        return rows;
    }

    private void runShizuku(Button btn, ProgressBar bar, TextView result) {
        if (!ShizukuOps.running()) {
            showResult(result, "Shizuku isn't running. Install Shizuku, open it and tap Start (it walks you through "
                    + "Wireless debugging), then come back and tap Check again.", cSub, alpha(cSub, 0x14));
            return;
        }
        if (!ShizukuOps.granted()) {
            ShizukuOps.request();
            toast("Allow Aegis in the Shizuku prompt, then tap Check again");
            return;
        }
        if (busy) { toast("Wait for the current task to finish"); return; }
        busy = true;
        setBusy(btn, true, "Reading…");
        hide(result);
        bar.setIndeterminate(true);
        show(bar);
        worker.execute(() -> {
            String text;
            int col, bgc;
            try {
                List<ShizukuOps.Use> uses = ShizukuOps.recentUses(Scanner.userApps(this));
                if (uses.isEmpty()) {
                    text = "✓ No app you installed has used the microphone, camera, location, SMS, contacts or "
                            + "clipboard recently.";
                    col = cGreen;
                    bgc = cGreenBg;
                } else {
                    StringBuilder sb = new StringBuilder("Most recent first. Anything you don't expect, like a "
                            + "torch app using the microphone, deserves a closer look:\n");
                    for (ShizukuOps.Use u : uses) {
                        sb.append("\n• ").append(u.label).append(": ").append(u.what).append(", ").append(u.ago);
                    }
                    text = sb.toString();
                    col = cText;
                    bgc = cInfoBg;
                }
            } catch (Throwable e) {
                text = "Couldn't read usage through Shizuku: " + e.getMessage();
                col = cSub;
                bgc = alpha(cSub, 0x14);
            }
            final String t = text;
            final int c = col, b = bgc;
            main.post(() -> {
                busy = false;
                setBusy(btn, false, "Check real usage");
                hide(bar);
                showResult(result, t, c, b);
            });
        });
    }

    private String dbStatus() {
        long t = prefs.getLong("db_time", 0);
        return t == 0 ? "Using the databases built into the app. Update now and then for the newest spy apps."
                : "Last updated: " + fmtTime(t);
    }

    // ------------------------------------------------------------------ PRIVACY tab

    private int tipNumber = 0;

    private View buildPrivacyTab() {
        LinearLayout page = page();

        TextView intro = text("Steps that protect you beyond this phone. Do them once, then every few months.",
                14, cSub, false);
        intro.setLineSpacing(0, 1.2f);
        intro.setPadding(dp(8), dp(6), dp(8), dp(6));
        page.addView(intro);

        page.addView(tip("Is someone forwarding your calls?",
                "Scammers secretly forward calls to steal OTPs. Dial *#21# and press call. Every line should say "
                        + "\"not forwarded\". To cancel ALL forwarding, dial ##002#.",
                "Dial *#21#", Finding.ActionType.DIAL, "*#21#"));

        page.addView(tip("Google account security check-up",
                "Shows signed-in devices, third-party access and weak settings. Remove any device you don't recognise.",
                "Open check-up", Finding.ActionType.OPEN_URL, "https://myaccount.google.com/security-checkup"));

        page.addView(tip("Devices signed in to your Google account",
                "If you see a phone or computer that isn't yours, sign it out and change your password.",
                "See devices", Finding.ActionType.OPEN_URL, "https://myaccount.google.com/device-activity"));

        page.addView(tip("Remove your phone number & address from Google Search",
                "Google's \"Results about you\" lets you request removal of search results showing your contact details.",
                "Results about you", Finding.ActionType.OPEN_URL, "https://myactivity.google.com/results-about-you"));

        page.addView(tip("Auto-delete your Google history",
                "Set Web & App Activity, Timeline (location) and YouTube history to auto-delete after 3 months.",
                "Activity controls", Finding.ActionType.OPEN_URL, "https://myactivity.google.com/activitycontrols"));

        page.addView(tip("WhatsApp, Instagram & Facebook sessions",
                "WhatsApp: Settings → Linked devices. Log out anything you don't recognise.\n"
                        + "Instagram / Facebook: Accounts Centre → Password and security → Where you're logged in.\n"
                        + "Also turn on two-step verification in each app.",
                null, null, null));

        page.addView(tip("Xiaomi, Redmi & POCO phones",
                "• Settings → Passwords & security → Privacy → Ad services → turn OFF personalised ads.\n"
                        + "• Settings → Passwords & security → Privacy → Special permissions: review Device admin apps "
                        + "and Usage access.\n"
                        + "• Turn on Find Device in your Mi account so you can lock or wipe a lost phone.",
                "Open Settings", Finding.ActionType.OPEN_SETTINGS, Settings.ACTION_SETTINGS));

        page.addView(tip("SIMs in your name, lost phones, second-hand phones",
                "Sanchar Saathi (Department of Telecommunications) shows every mobile number issued in your name "
                        + "(TAFCOP): report any you don't use. It also blocks a lost or stolen phone (CEIR) and checks a "
                        + "second-hand phone's IMEI before you buy it.",
                "Open Sanchar Saathi", Finding.ActionType.OPEN_URL, "https://sancharsaathi.gov.in/"));

        page.addView(tip("Never share your screen with a \"bank officer\"",
                "No bank, UPI app or government office will ask you to install AnyDesk, TeamViewer, RustDesk or any "
                        + "screen-sharing app, or to merge a call. If someone did and you shared a code: uninstall the app, "
                        + "change your UPI PIN, call your bank, then call 1930. Aegis flags these apps in every scan.",
                null, null, null));

        page.addView(tip("Google Play Protect",
                "Open the Play Store → tap your profile picture → Play Protect → make sure \"Scan apps\" is on.",
                null, null, null));

        LinearLayout help = card();
        GradientDrawable hb = new GradientDrawable();
        hb.setColor(cRedBg);
        hb.setCornerRadius(dp(18));
        hb.setStroke(dp(1), alpha(cRed, 0x40));
        help.setBackground(hb);
        help.addView(cardHeader("🆘", "Get help", cRed, alpha(cRed, 0x22)));
        TextView ht = cardText("If you think a specific person (partner, family member, employer) is spying on you, "
                + "removing their app may alert them. Check your phone in a safe place first, and consider getting "
                + "help. In India, report cyber crime at cybercrime.gov.in or call 1930.");
        ht.setTextColor(cText);
        help.addView(ht);
        LinearLayout row = new LinearLayout(this);
        Button call = smallButton("Call 1930", cRed);
        call.setOnClickListener(v -> launch(new Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930"))));
        Button web = smallButton("cybercrime.gov.in", cPrimary);
        web.setOnClickListener(v -> launch(new Intent(Intent.ACTION_VIEW, Uri.parse("https://cybercrime.gov.in"))));
        row.addView(call);
        row.addView(web);
        help.addView(row);
        TextView chakshuText = cardText("Got a fraud call, SMS or WhatsApp? Report it on Sanchar Saathi (Chakshu) "
                + "so the government can block the number.");
        chakshuText.setTextColor(cText);
        chakshuText.setPadding(0, dp(12), 0, 0);
        help.addView(chakshuText);
        Button chakshu = smallButton("Report to Chakshu", cPrimary);
        chakshu.setOnClickListener(v -> launch(new Intent(Intent.ACTION_VIEW, Uri.parse(CHAKSHU_URL))));
        help.addView(chakshu);
        page.addView(help);

        TextView credits = text("Detection data: AssoEchap stalkerware-indicators (CC BY 4.0), AndroDR / "
                + "android-sigma-rules (CC BY 4.0), MVT indicators (Amnesty International, Citizen Lab and others), "
                + "Exodus Privacy trackers (ODbL 1.0), malware-filter phishing list (CC BY-SA 4.0), Phishing Army, "
                + "abuse.ch MalwareBazaar & URLhaus, Have I Been Pwned.", 11, cSub, false);
        credits.setGravity(Gravity.CENTER);
        credits.setLineSpacing(0, 1.2f);
        credits.setPadding(dp(12), dp(16), dp(12), dp(28));
        page.addView(credits);
        return page;
    }

    private View tip(String title, String body, String btnLabel, Finding.ActionType type, String target) {
        LinearLayout c = card();
        c.addView(cardHeader(String.valueOf(++tipNumber), title, cPrimary, alpha(cPrimary, 0x1F)));
        c.addView(cardText(body));
        if (btnLabel != null) {
            Button b = smallButton(btnLabel, cPrimary);
            b.setOnClickListener(v -> runAction(new Finding.Action(btnLabel, type, target), c));
            c.addView(b);
        }
        return c;
    }

    // ------------------------------------------------------------------ motion helpers

    /** Cards rise and fade in one after another. */
    private void enter(View v, int order) {
        v.setAlpha(0f);
        v.setTranslationY(dp(18));
        v.animate().alpha(1f).translationY(0).setStartDelay(Math.min(order * 40L, 480L))
                .setDuration(320).setInterpolator(EASE).start();
    }

    private void show(View v) {
        if (v.getVisibility() == View.VISIBLE && v.getAlpha() == 1f) return;
        v.animate().cancel();
        v.setAlpha(0f);
        v.setVisibility(View.VISIBLE);
        v.animate().alpha(1f).setStartDelay(0).setDuration(220).setInterpolator(EASE).start();
    }

    private void hide(View v) {
        v.animate().cancel();
        v.setVisibility(View.GONE);
    }

    /** Grows a GONE view from zero height to its natural height. */
    private void expand(View v) {
        View parent = (View) v.getParent();
        int width = parent.getWidth() - parent.getPaddingLeft() - parent.getPaddingRight();
        v.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
        int target = v.getMeasuredHeight();
        ViewGroup.LayoutParams lp = v.getLayoutParams();
        lp.height = 0;
        v.setAlpha(0f);
        v.setVisibility(View.VISIBLE);
        v.setLayoutParams(lp);
        ValueAnimator a = ValueAnimator.ofInt(0, target);
        a.setDuration(Math.min(450, 180 + target / 6));
        a.setInterpolator(EASE);
        a.addUpdateListener(x -> {
            lp.height = (int) x.getAnimatedValue();
            v.setAlpha(x.getAnimatedFraction());
            v.setLayoutParams(lp);
        });
        a.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override public void onAnimationEnd(android.animation.Animator an) {
                lp.height = ViewGroup.LayoutParams.WRAP_CONTENT;
                v.setAlpha(1f);
                v.setLayoutParams(lp);
            }
        });
        a.start();
    }

    /** Shrinks a view (and its margins) to nothing, then hides it. */
    private void collapse(View v, Runnable after) {
        int start = v.getHeight();
        ViewGroup.LayoutParams lp = v.getLayoutParams();
        ViewGroup.MarginLayoutParams mlp = lp instanceof ViewGroup.MarginLayoutParams
                ? (ViewGroup.MarginLayoutParams) lp : null;
        int top = mlp != null ? mlp.topMargin : 0, bottom = mlp != null ? mlp.bottomMargin : 0;
        ValueAnimator a = ValueAnimator.ofFloat(1f, 0f);
        a.setDuration(Math.min(400, 180 + start / 6));
        a.setInterpolator(EASE);
        a.addUpdateListener(x -> {
            float f = (float) x.getAnimatedValue();
            lp.height = Math.round(start * f);
            if (mlp != null) {
                mlp.topMargin = Math.round(top * f);
                mlp.bottomMargin = Math.round(bottom * f);
            }
            v.setAlpha(f);
            v.setLayoutParams(lp);
        });
        a.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override public void onAnimationEnd(android.animation.Animator an) {
                v.setVisibility(View.GONE);
                lp.height = ViewGroup.LayoutParams.WRAP_CONTENT;
                if (mlp != null) {
                    mlp.topMargin = top;
                    mlp.bottomMargin = bottom;
                }
                v.setAlpha(1f);
                v.setLayoutParams(lp);
                if (after != null) after.run();
            }
        });
        a.start();
    }

    private void shake(View v) {
        ObjectAnimator.ofFloat(v, "translationX", 0, dp(8), -dp(8), dp(5), -dp(5), 0).setDuration(320).start();
        v.requestFocus();
    }

    private void setBusy(Button b, boolean on, String label) {
        b.setEnabled(!on);
        if (label != null) b.setText(label);
        b.animate().alpha(on ? 0.65f : 1f).setDuration(160).start();
    }

    private void showResult(TextView t, String msg, int fgc, int bgc) {
        t.setText(msg);
        t.setTextColor(fgc);
        t.setBackground(round(bgc, 12));
        show(t);
    }

    private static int offsetTop(View v, View ancestor) {
        int y = 0;
        while (v != null && v != ancestor) {
            y += v.getTop();
            v = v.getParent() instanceof View ? (View) v.getParent() : null;
        }
        return y;
    }

    // ------------------------------------------------------------------ small UI helpers

    private LinearLayout page() {
        LinearLayout p = new LinearLayout(this);
        p.setOrientation(LinearLayout.VERTICAL);
        p.setPadding(dp(14), dp(14), dp(14), dp(14));
        return p;
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable d = new GradientDrawable();
        d.setColor(cCard);
        d.setCornerRadius(dp(18));
        d.setStroke(dp(1), cLine);
        c.setBackground(d);
        if (!dark) c.setElevation(dp(1));
        c.setPadding(dp(18), dp(16), dp(18), dp(16));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(6), 0, dp(6));
        c.setLayoutParams(lp);
        return c;
    }

    /** Card title with a small coloured icon tile on the left. */
    private View cardHeader(String icon, String title, int fgc, int bgc) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, 0, 0, dp(8));
        TextView ic = text(icon, icon.length() <= 2 && Character.isDigit(icon.charAt(0)) ? 15 : 18, fgc, true);
        ic.setGravity(Gravity.CENTER);
        ic.setBackground(round(bgc, 12));
        row.addView(ic, new LinearLayout.LayoutParams(dp(38), dp(38)));
        TextView t = text(title, 17, cText, true);
        t.setPadding(dp(12), 0, 0, 0);
        row.addView(t, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private TextView cardText(String s) {
        TextView t = text(s, 14, cSub, false);
        t.setLineSpacing(0, 1.2f);
        t.setPadding(0, dp(2), 0, dp(8));
        return t;
    }

    private TextView statusText() {
        TextView t = text("", 13, cSub, false);
        t.setSingleLine(true);
        t.setEllipsize(TextUtils.TruncateAt.END);
        t.setPadding(0, dp(6), 0, 0);
        t.setVisibility(View.GONE);
        return t;
    }

    private TextView resultBox() {
        TextView t = text("", 14, cSub, false);
        t.setLineSpacing(0, 1.2f);
        t.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(8), 0, dp(4));
        t.setLayoutParams(lp);
        t.setVisibility(View.GONE);
        return t;
    }

    private ProgressBar thinProgress() {
        ProgressBar p = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        p.setMax(100);
        p.setProgressTintList(ColorStateList.valueOf(cPrimary));
        p.setProgressBackgroundTintList(ColorStateList.valueOf(cTrack));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(6));
        lp.topMargin = dp(4);
        p.setLayoutParams(lp);
        p.setVisibility(View.GONE);
        return p;
    }

    private TextView linkText(String s, String url) {
        TextView t = text(s, 14, cPrimary, true);
        t.setPadding(dp(4), dp(10), dp(4), dp(10));
        t.setBackground(ripple(Color.TRANSPARENT, cPrimary, 10));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(4);
        t.setLayoutParams(lp);
        t.setOnClickListener(v -> launch(new Intent(Intent.ACTION_VIEW, Uri.parse(url))));
        return t;
    }

    /** bold = medium weight, which reads cleaner than full bold at small sizes. */
    private TextView text(String s, float sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        t.setTypeface(bold ? Typeface.create("sans-serif-medium", Typeface.NORMAL) : Typeface.DEFAULT);
        t.setTextIsSelectable(false);
        return t;
    }

    private LinearLayout.LayoutParams wrapCenter() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.gravity = Gravity.CENTER_HORIZONTAL;
        return lp;
    }

    private EditText input(String hint, boolean password) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setTextColor(cText);
        e.setHintTextColor(alpha(cSub, 0xB0));
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        e.setSingleLine(true);
        e.setInputType(password
                ? InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD
                : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        // Border turns to the accent colour while typing.
        GradientDrawable idle = new GradientDrawable();
        idle.setColor(cBg);
        idle.setCornerRadius(dp(12));
        idle.setStroke(dp(1), cLine);
        GradientDrawable focus = new GradientDrawable();
        focus.setColor(cCard);
        focus.setCornerRadius(dp(12));
        focus.setStroke(dp(2), cPrimary);
        StateListDrawable s = new StateListDrawable();
        s.addState(new int[]{android.R.attr.state_focused}, focus);
        s.addState(new int[]{}, idle);
        s.setEnterFadeDuration(150);
        s.setExitFadeDuration(150);
        e.setBackground(s);
        e.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(6), 0, dp(10));
        e.setLayoutParams(lp);
        return e;
    }

    private Button primaryButton(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(16);
        b.setTextColor(Color.WHITE);
        b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        b.setLetterSpacing(0.01f);
        b.setBackground(ripple(cPrimary, Color.WHITE, 26));
        b.setStateListAnimator(pressScale());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        lp.setMargins(0, dp(6), 0, dp(6));
        b.setLayoutParams(lp);
        return b;
    }

    /** Tonal pill button: tinted background, coloured label. */
    private Button smallButton(String label, int color) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(13);
        b.setTextColor(color);
        b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        b.setMinHeight(0);
        b.setMinimumHeight(0);
        b.setMinWidth(0);
        b.setMinimumWidth(0);
        b.setBackground(ripple(alpha(color, 0x1C), color, 18));
        b.setStateListAnimator(pressScale());
        b.setPadding(dp(16), dp(9), dp(16), dp(9));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(4), dp(8), dp(4));
        b.setLayoutParams(lp);
        b.setGravity(Gravity.CENTER);
        return b;
    }

    /** Buttons shrink slightly while pressed, then spring back. */
    private StateListAnimator pressScale() {
        StateListAnimator s = new StateListAnimator();
        AnimatorSet down = new AnimatorSet();
        down.playTogether(ObjectAnimator.ofFloat(null, "scaleX", 0.96f), ObjectAnimator.ofFloat(null, "scaleY", 0.96f));
        down.setDuration(90);
        AnimatorSet up = new AnimatorSet();
        up.playTogether(ObjectAnimator.ofFloat(null, "scaleX", 1f), ObjectAnimator.ofFloat(null, "scaleY", 1f));
        up.setDuration(160);
        up.setInterpolator(EASE);
        s.addState(new int[]{android.R.attr.state_pressed, android.R.attr.state_enabled}, down);
        s.addState(new int[]{}, up);
        return s;
    }

    private Drawable ripple(int fill, int rippleColor, int radiusDp) {
        GradientDrawable content = round(fill, radiusDp);
        GradientDrawable mask = round(Color.WHITE, radiusDp);
        return new RippleDrawable(ColorStateList.valueOf(alpha(rippleColor, 0x33)), content, mask);
    }

    private GradientDrawable round(int color, int radiusDp) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(radiusDp));
        return d;
    }

    private static int alpha(int color, int a) {
        return (a << 24) | (color & 0x00FFFFFF);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

    private static String fmtTime(long t) {
        return new SimpleDateFormat("d MMM yyyy, h:mm a", Locale.getDefault()).format(new Date(t));
    }
}
