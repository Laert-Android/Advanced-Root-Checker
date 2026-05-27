package com.laert.rootchecker;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.view.animation.ScaleAnimation;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

public class RootCheckerActivity extends Activity {

    private LinearLayout resultsLayout;
    private LinearLayout deviceInfoLayout;
    private TextView summaryTitle;
    private TextView summarySubtitle;
    private LinearLayout summaryCard;
    private Button scanButton;
    private ProgressBar progressBar;
    private TextView progressText;
    private LinearLayout progressContainer;
    private Handler mainHandler;

    private static final int BG_PRIMARY   = 0xFF0F1923;
    private static final int BG_CARD      = 0xFF1A2733;
    private static final int TEAL_PRIMARY = 0xFF4DB6AC;
    private static final int GREEN_PASS   = 0xFF4CAF50;
    private static final int RED_FAIL     = 0xFFEF5350;
    private static final int ORANGE_WARN  = 0xFFFF9800;
    private static final int TEXT_PRIMARY = 0xFFE0F2F1;
    private static final int TEXT_SEC     = 0xFF80CBC4;
    private static final int TEXT_HINT    = 0xFF546E7A;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mainHandler = new Handler(Looper.getMainLooper());
        buildUI();
    }

    private void buildUI() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG_PRIMARY);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(40), dp(20), dp(32));
        root.setBackgroundColor(BG_PRIMARY);

        // Title
        TextView appTitle = new TextView(this);
        appTitle.setText("Advanced Root Checker");
        appTitle.setTextSize(22f);
        appTitle.setTextColor(TEAL_PRIMARY);
        appTitle.setTypeface(Typeface.DEFAULT_BOLD);
        appTitle.setGravity(Gravity.CENTER);
        root.addView(appTitle);

        TextView appSub = new TextView(this);
        appSub.setText("No Ads  |  No Tracking  |  Open Source");
        appSub.setTextSize(11f);
        appSub.setTextColor(TEXT_HINT);
        appSub.setGravity(Gravity.CENTER);
        appSub.setPadding(0, dp(4), 0, dp(20));
        root.addView(appSub);

        // Summary card
        summaryCard = new LinearLayout(this);
        summaryCard.setOrientation(LinearLayout.VERTICAL);
        summaryCard.setGravity(Gravity.CENTER);
        summaryCard.setPadding(dp(20), dp(24), dp(20), dp(24));
        setRoundedBg(summaryCard, BG_CARD, 24);

        summaryTitle = new TextView(this);
        summaryTitle.setText("Ready to Scan");
        summaryTitle.setTextSize(20f);
        summaryTitle.setTextColor(TEXT_PRIMARY);
        summaryTitle.setTypeface(Typeface.DEFAULT_BOLD);
        summaryTitle.setGravity(Gravity.CENTER);
        summaryCard.addView(summaryTitle);

        summarySubtitle = new TextView(this);
        summarySubtitle.setText("Tap SCAN FOR ROOT to check your device");
        summarySubtitle.setTextSize(12f);
        summarySubtitle.setTextColor(TEXT_SEC);
        summarySubtitle.setGravity(Gravity.CENTER);
        summarySubtitle.setPadding(0, dp(6), 0, 0);
        summaryCard.addView(summarySubtitle);

        root.addView(summaryCard);
        root.addView(spacer(16));

        // Progress container
        progressContainer = new LinearLayout(this);
        progressContainer.setOrientation(LinearLayout.VERTICAL);
        progressContainer.setVisibility(View.GONE);

        progressText = new TextView(this);
        progressText.setText("Scanning... 0%");
        progressText.setTextSize(12f);
        progressText.setTextColor(TEAL_PRIMARY);
        progressText.setGravity(Gravity.CENTER);
        progressContainer.addView(progressText);
        progressContainer.addView(spacer(4));

        progressBar = new ProgressBar(this, null,
            android.R.attr.progressBarStyleHorizontal);
        progressBar.setMax(100);
        progressBar.setProgress(0);
        progressBar.setProgressTintList(
            android.content.res.ColorStateList.valueOf(TEAL_PRIMARY));
        progressContainer.addView(progressBar);
        progressContainer.addView(spacer(8));
        root.addView(progressContainer);

        // Scan button
        scanButton = new Button(this);
        scanButton.setText("SCAN FOR ROOT");
        scanButton.setTextColor(BG_PRIMARY);
        scanButton.setTextSize(14f);
        scanButton.setTypeface(Typeface.DEFAULT_BOLD);
        scanButton.setAllCaps(true);
        setRoundedBg(scanButton, TEAL_PRIMARY, 50);
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(52));
        root.addView(scanButton, btnLp);
        root.addView(spacer(24));

        scanButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                startScan();
            }
        });

        // Check results divider
        root.addView(makeDivider("CHECK RESULTS"));
        root.addView(spacer(12));

        // Results layout
        resultsLayout = new LinearLayout(this);
        resultsLayout.setOrientation(LinearLayout.VERTICAL);

        TextView emptyHint = new TextView(this);
        emptyHint.setText("No results yet. Run a scan to see details.");
        emptyHint.setTextColor(TEXT_HINT);
        emptyHint.setTextSize(12f);
        emptyHint.setGravity(Gravity.CENTER);
        emptyHint.setPadding(0, dp(12), 0, dp(12));
        resultsLayout.addView(emptyHint);
        root.addView(resultsLayout);

        root.addView(spacer(24));

        // Device info divider
        root.addView(makeDivider("DEVICE SECURITY INFO"));
        root.addView(spacer(12));

        // Device info layout
        deviceInfoLayout = new LinearLayout(this);
        deviceInfoLayout.setOrientation(LinearLayout.VERTICAL);
        root.addView(deviceInfoLayout);

        // Load device info immediately
        loadDeviceInfo();

        root.addView(spacer(20));
        TextView footer = new TextView(this);
        footer.setText("All checks run locally. No data sent anywhere.");
        footer.setTextColor(TEXT_HINT);
        footer.setTextSize(10f);
        footer.setGravity(Gravity.CENTER);
        root.addView(footer);

        scroll.addView(root);
        setContentView(scroll);
    }

    private void loadDeviceInfo() {
        DeviceInfo.InfoItem[] items = DeviceInfo.getDeviceInfo(this);
        for (int i = 0; i < items.length; i++) {
            addInfoRow(items[i]);
        }
    }

    private void addInfoRow(DeviceInfo.InfoItem item) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setPadding(dp(16), dp(12), dp(16), dp(12));
        card.setGravity(Gravity.CENTER_VERTICAL);
        setRoundedBg(card, BG_CARD, 14);

        // Warning dot
        TextView dot = new TextView(this);
        dot.setText(" \u25cf ");
        dot.setTextSize(10f);
        dot.setTextColor(item.isWarning ? ORANGE_WARN : TEAL_PRIMARY);
        card.addView(dot);

        // Info
        LinearLayout info = new LinearLayout(this);
        info.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        card.addView(info, infoLp);

        TextView label = new TextView(this);
        label.setText(item.label);
        label.setTextColor(TEXT_HINT);
        label.setTextSize(10f);
        label.setTypeface(Typeface.DEFAULT_BOLD);
        info.addView(label);

        TextView value = new TextView(this);
        value.setText(item.value);
        value.setTextColor(item.isWarning ? ORANGE_WARN : TEXT_PRIMARY);
        value.setTextSize(12f);
        info.addView(value);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, dp(8));
        deviceInfoLayout.addView(card, lp);
    }

    private LinearLayout makeDivider(String label) {
        LinearLayout dividerRow = new LinearLayout(this);
        dividerRow.setOrientation(LinearLayout.HORIZONTAL);
        dividerRow.setGravity(Gravity.CENTER_VERTICAL);

        View divL = new View(this);
        divL.setBackgroundColor(0xFF1E2F3D);
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(0, dp(1), 1f);
        dividerRow.addView(divL, dlp);

        TextView divLabel = new TextView(this);
        divLabel.setText("  " + label + "  ");
        divLabel.setTextSize(10f);
        divLabel.setTextColor(TEXT_HINT);
        divLabel.setTypeface(Typeface.DEFAULT_BOLD);
        dividerRow.addView(divLabel);

        View divR = new View(this);
        divR.setBackgroundColor(0xFF1E2F3D);
        LinearLayout.LayoutParams drp = new LinearLayout.LayoutParams(0, dp(1), 1f);
        dividerRow.addView(divR, drp);

        return dividerRow;
    }

    private void startScan() {
        scanButton.setEnabled(false);
        setRoundedBg(scanButton, TEXT_HINT, 50);
        scanButton.setText("SCANNING...");
        resultsLayout.removeAllViews();
        progressContainer.setVisibility(View.VISIBLE);
        progressBar.setProgress(0);
        setRoundedBg(summaryCard, BG_CARD, 24);
        summaryTitle.setText("Scanning...");
        summaryTitle.setTextColor(TEAL_PRIMARY);
        summarySubtitle.setText("Running all 15 checks on your device");
        summarySubtitle.setTextColor(TEXT_SEC);

        Thread t = new Thread(new Runnable() {
            public void run() {
                RootDetector detector = new RootDetector();
                final RootDetector.CheckResult[] checks = detector.runAllChecks();
                final int total = checks.length;
                int rootCount = 0;

                for (int i = 0; i < checks.length; i++) {
                    final int progress = (int)(((float)(i+1)/total)*100);
                    final RootDetector.CheckResult check = checks[i];
                    if (check.detected) rootCount++;
                    final int idx = i + 1;

                    mainHandler.post(new Runnable() {
                        public void run() {
                            progressBar.setProgress(progress);
                            progressText.setText("Scanning... "+progress+"%  ("+idx+"/"+total+")");
                            addResultRow(check);
                        }
                    });
                    try { Thread.sleep(150); } catch (InterruptedException e) { break; }
                }

                final int detected = rootCount;
                mainHandler.post(new Runnable() {
                    public void run() {
                        progressContainer.setVisibility(View.GONE);
                        scanButton.setEnabled(true);
                        setRoundedBg(scanButton, TEAL_PRIMARY, 50);
                        scanButton.setText("SCAN AGAIN");
                        updateSummary(detected, total);
                    }
                });
            }
        });
        t.start();
    }

    private void addResultRow(RootDetector.CheckResult check) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setPadding(dp(16), dp(12), dp(16), dp(12));
        card.setGravity(Gravity.CENTER_VERTICAL);
        setRoundedBg(card, BG_CARD, 14);

        TextView pill = new TextView(this);
        pill.setText(check.detected ? " FAIL " : " PASS ");
        pill.setTextSize(9f);
        pill.setTypeface(Typeface.DEFAULT_BOLD);
        pill.setTextColor(Color.WHITE);
        pill.setGravity(Gravity.CENTER);
        setRoundedBg(pill, check.detected ? RED_FAIL : GREEN_PASS, 20);
        pill.setPadding(dp(6), dp(3), dp(6), dp(3));
        LinearLayout.LayoutParams pillLp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        pillLp.setMargins(0, 0, dp(10), 0);
        card.addView(pill, pillLp);

        LinearLayout info = new LinearLayout(this);
        info.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        card.addView(info, infoLp);

        TextView name = new TextView(this);
        name.setText(check.name);
        name.setTextColor(TEXT_PRIMARY);
        name.setTextSize(13f);
        name.setTypeface(Typeface.DEFAULT_BOLD);
        info.addView(name);

        TextView detail = new TextView(this);
        detail.setText(check.detail);
        detail.setTextColor(TEXT_SEC);
        detail.setTextSize(11f);
        info.addView(detail);

        AlphaAnimation anim = new AlphaAnimation(0f, 1f);
        anim.setDuration(200);
        card.startAnimation(anim);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, dp(8));
        resultsLayout.addView(card, lp);
    }

    private void updateSummary(int detected, int total) {
        ScaleAnimation scale = new ScaleAnimation(
            0.95f, 1f, 0.95f, 1f,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f);
        scale.setDuration(300);
        summaryCard.startAnimation(scale);

        if (detected == 0) {
            setRoundedBg(summaryCard, 0xFF0D2B1A, 24);
            summaryTitle.setText("Device is Clean");
            summaryTitle.setTextColor(GREEN_PASS);
            summarySubtitle.setText("All "+total+" checks passed - No root indicators found");
            summarySubtitle.setTextColor(0xFF81C784);
        } else if (detected <= 2) {
            setRoundedBg(summaryCard, 0xFF2B1F0D, 24);
            summaryTitle.setText("Possible Root");
            summaryTitle.setTextColor(ORANGE_WARN);
            summarySubtitle.setText(detected+" of "+total+" checks flagged");
            summarySubtitle.setTextColor(0xFFFFCC80);
        } else {
            setRoundedBg(summaryCard, 0xFF2B0D0D, 24);
            summaryTitle.setText("Root Detected!");
            summaryTitle.setTextColor(RED_FAIL);
            summarySubtitle.setText(detected+" of "+total+" checks flagged");
            summarySubtitle.setTextColor(0xFFEF9A9A);
        }
    }

    private void setRoundedBg(View view, int color, int radiusDp) {
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(color);
        gd.setCornerRadius(dp(radiusDp));
        view.setBackground(gd);
    }

    private View spacer(int dp) {
        View v = new View(this);
        v.setMinimumHeight(dp(dp));
        return v;
    }

    private int dp(int val) {
        return (int)(val * getResources().getDisplayMetrics().density);
    }
}
