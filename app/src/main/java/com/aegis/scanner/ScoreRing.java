package com.aegis.scanner;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.view.View;
import android.view.animation.LinearInterpolator;
import android.view.animation.PathInterpolator;

/**
 * The round gauge at the top of the Scan tab.
 * Idle: a shield. Scanning: a progress ring with a moving highlight. Done: a full ring in the result colour.
 */
class ScoreRing extends View {

    private final Paint track = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint arc = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glow = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint shieldFill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint shieldMark = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint bigText = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint smallText = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF box = new RectF();
    private final Path shield = new Path();
    private final Path check = new Path();

    private float progress = 0f;       // 0..1, what is drawn
    private float spin = 0f;           // degrees, moving highlight while scanning
    private boolean scanning = false;
    private boolean showShield = true;
    private String big = "", small = "";

    private ValueAnimator progressAnim, spinAnim, colorAnim;
    private static final PathInterpolator EASE = new PathInterpolator(0.2f, 0f, 0f, 1f);

    ScoreRing(Context c, int trackColor, int arcColor, int textColor, int subColor) {
        super(c);
        track.setStyle(Paint.Style.STROKE);
        track.setColor(trackColor);
        arc.setStyle(Paint.Style.STROKE);
        arc.setStrokeCap(Paint.Cap.ROUND);
        arc.setColor(arcColor);
        glow.setStyle(Paint.Style.STROKE);
        glow.setStrokeCap(Paint.Cap.ROUND);
        shieldFill.setStyle(Paint.Style.FILL);
        shieldMark.setStyle(Paint.Style.STROKE);
        shieldMark.setStrokeCap(Paint.Cap.ROUND);
        shieldMark.setStrokeJoin(Paint.Join.ROUND);
        bigText.setTextAlign(Paint.Align.CENTER);
        bigText.setColor(textColor);
        bigText.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        smallText.setTextAlign(Paint.Align.CENTER);
        smallText.setColor(subColor);
        smallText.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        applyArcColor(arcColor);
    }

    /** Shield with a tick, no ring progress. */
    void setIdle() {
        stopSpin();
        scanning = false;
        showShield = true;
        animateProgress(0f, 300);
        invalidate();
    }

    void setScanning(int color) {
        scanning = true;
        showShield = false;
        big = "0%";
        small = "scanning";
        animateColor(color);
        progress = 0f;
        startSpin();
        invalidate();
    }

    void setPercent(int pct) {
        big = Math.max(0, Math.min(100, pct)) + "%";
        animateProgress(pct / 100f, 420);
    }

    /** Final state: full ring in the result colour with a short label in the middle. */
    void setResult(int color, String bigLabel, String smallLabel) {
        scanning = false;
        stopSpin();
        showShield = false;
        big = bigLabel;
        small = smallLabel;
        animateColor(color);
        animateProgress(1f, 700);
    }

    // ---------------------------------------------------------------- animation

    private void animateProgress(float to, long ms) {
        if (progressAnim != null) progressAnim.cancel();
        progressAnim = ValueAnimator.ofFloat(progress, to);
        progressAnim.setDuration(ms);
        progressAnim.setInterpolator(EASE);
        progressAnim.addUpdateListener(a -> { progress = (float) a.getAnimatedValue(); invalidate(); });
        progressAnim.start();
    }

    private void animateColor(int to) {
        if (colorAnim != null) colorAnim.cancel();
        colorAnim = ValueAnimator.ofObject(new ArgbEvaluator(), arc.getColor(), to);
        colorAnim.setDuration(400);
        colorAnim.addUpdateListener(a -> { applyArcColor((int) a.getAnimatedValue()); invalidate(); });
        colorAnim.start();
    }

    private void applyArcColor(int c) {
        arc.setColor(c);
        glow.setColor(c);
        glow.setAlpha(70);
        shieldFill.setColor(c);
        shieldFill.setAlpha(36);
        shieldMark.setColor(c);
    }

    private void startSpin() {
        stopSpin();
        spinAnim = ValueAnimator.ofFloat(0f, 360f);
        spinAnim.setDuration(1400);
        spinAnim.setRepeatCount(ValueAnimator.INFINITE);
        spinAnim.setInterpolator(new LinearInterpolator());
        spinAnim.addUpdateListener(a -> { spin = (float) a.getAnimatedValue(); invalidate(); });
        spinAnim.start();
    }

    private void stopSpin() {
        if (spinAnim != null) spinAnim.cancel();
        spinAnim = null;
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        stopSpin();
        if (progressAnim != null) progressAnim.cancel();
        if (colorAnim != null) colorAnim.cancel();
    }

    // ---------------------------------------------------------------- drawing

    @Override
    protected void onDraw(Canvas c) {
        float size = Math.min(getWidth(), getHeight());
        float stroke = size * 0.075f;
        float cx = getWidth() / 2f, cy = getHeight() / 2f;
        float r = size / 2f - stroke;
        box.set(cx - r, cy - r, cx + r, cy + r);
        track.setStrokeWidth(stroke);
        arc.setStrokeWidth(stroke);
        glow.setStrokeWidth(stroke * 1.9f);

        c.drawCircle(cx, cy, r, track);
        if (scanning) c.drawArc(box, spin - 90f, 40f, false, glow);
        if (progress > 0.002f) c.drawArc(box, -90f, 360f * progress, false, arc);

        if (showShield) {
            drawShield(c, cx, cy, size * 0.46f);
        } else {
            bigText.setTextSize(size * 0.25f);
            smallText.setTextSize(size * 0.095f);
            c.drawText(big, cx, cy + size * 0.06f, bigText);
            c.drawText(small, cx, cy + size * 0.22f, smallText);
        }
    }

    private void drawShield(Canvas c, float cx, float cy, float s) {
        float x = cx - s / 2f, y = cy - s / 2f;
        shield.reset();
        shield.moveTo(x + .50f * s, y + .04f * s);
        shield.lineTo(x + .90f * s, y + .19f * s);
        shield.lineTo(x + .90f * s, y + .48f * s);
        shield.cubicTo(x + .90f * s, y + .74f * s, x + .72f * s, y + .91f * s, x + .50f * s, y + .98f * s);
        shield.cubicTo(x + .28f * s, y + .91f * s, x + .10f * s, y + .74f * s, x + .10f * s, y + .48f * s);
        shield.lineTo(x + .10f * s, y + .19f * s);
        shield.close();
        c.drawPath(shield, shieldFill);
        shieldMark.setStrokeWidth(s * 0.06f);
        c.drawPath(shield, shieldMark);
        check.reset();
        check.moveTo(x + .32f * s, y + .52f * s);
        check.lineTo(x + .45f * s, y + .65f * s);
        check.lineTo(x + .69f * s, y + .38f * s);
        shieldMark.setStrokeWidth(s * 0.085f);
        c.drawPath(check, shieldMark);
    }
}
