package com.laert.rootchecker;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
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
    private LinearLayout historyLayout;
    private TextView summaryTitle;
    private TextView summarySubtitle;
    private TextView scoreText;
    private LinearLayout summaryCard;
    private Button scanButton;
    private ProgressBar progressBar;
    private TextView progressText;
    private LinearLayout progressContainer;
    private Handler mainHandler;
    private SharedPreferences prefs;

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
        prefs = getSharedPreferences("scan_history", Context.MODE_PRIVATE);
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
        appSub.setPadding(0, dp(4), 0, dp(16));
        root.addView(appSub);

        // Keep Android Open banner
        root.addView(buildKeepOpenBanner());
        root.addView(spacer(16));

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

        // Risk score
        scoreText = new TextView(this);
        scoreText.setText("");
        scoreText.setTextSize(36f);
        scoreText.setTypeface(Typeface.DEFAULT_BOLD);
        scoreText.setGravity(Gravity.CENTER);
        scoreText.setPadding(0, dp(8), 0, 0);
        summaryCard.addView(scoreText);

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

        // Scan history section
        root.addView(makeDivider("SCAN HISTORY"));
        root.addView(spacer(12));
        historyLayout = new LinearLayout(this);
        historyLayout.setOrientation(LinearLayout.VERTICAL);
        root.addView(historyLayout);
        loadHistory();
        root.addView(spacer(24));

        // Check results section
        root.addView(makeDivider("CHECK RESULTS"));
        root.addView(spacer(8));

        TextView tapHint = new TextView(this);
        tapHint.setText("Tap any result to learn more");
        tapHint.setTextSize(11f);
        tapHint.setTextColor(TEXT_HINT);
        tapHint.setGravity(Gravity.CENTER);
        root.addView(tapHint);
        root.addView(spacer(8));

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

        // Device security info section
        root.addView(makeDivider("DEVICE SECURITY INFO"));
        root.addView(spacer(12));
        deviceInfoLayout = new LinearLayout(this);
        deviceInfoLayout.setOrientation(LinearLayout.VERTICAL);
        root.addView(deviceInfoLayout);
        loadDeviceInfo();
        root.addView(spacer(24));

        // Importance of root section
        root.addView(makeDivider("IMPORTANCE OF ROOT"));
        root.addView(spacer(12));
        root.addView(buildImportanceSection());
        root.addView(spacer(24));

        // Footer
        TextView footer = new TextView(this);
        footer.setText("All checks run locally. No data sent anywhere.\nv3.1");
        footer.setTextColor(TEXT_HINT);
        footer.setTextSize(10f);
        footer.setGravity(Gravity.CENTER);
        root.addView(footer);

        scroll.addView(root);
        setContentView(scroll);
    }

    private void loadHistory() {
        historyLayout.removeAllViews();
        String h1 = prefs.getString("scan_1", "");
        String h2 = prefs.getString("scan_2", "");
        String h3 = prefs.getString("scan_3", "");

        if (h1.isEmpty() && h2.isEmpty() && h3.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText("No previous scans yet.");
            empty.setTextColor(TEXT_HINT);
            empty.setTextSize(12f);
            empty.setGravity(Gravity.CENTER);
            historyLayout.addView(empty);
            return;
        }

        if (!h3.isEmpty()) addHistoryRow(h3);
        if (!h2.isEmpty()) addHistoryRow(h2);
        if (!h1.isEmpty()) addHistoryRow(h1);
    }

    private void addHistoryRow(String entry) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(dp(16), dp(10), dp(16), dp(10));
        row.setGravity(Gravity.CENTER_VERTICAL);
        setRoundedBg(row, BG_CARD, 12);

        TextView text = new TextView(this);
        text.setText(entry);
        text.setTextColor(TEXT_SEC);
        text.setTextSize(12f);
        row.addView(text);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, dp(6));
        historyLayout.addView(row, lp);
    }

    private void saveHistory(int detected, int total, int score) {
        String h1 = prefs.getString("scan_1", "");
        String h2 = prefs.getString("scan_2", "");
        String now = new java.util.Date().toString().substring(0, 19);
        String entry = now + " | " + detected + "/" + total + " flags | Score: " + score + "/100";
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("scan_3", h2);
        editor.putString("scan_2", h1);
        editor.putString("scan_1", entry);
        editor.apply();
    }

    private LinearLayout buildKeepOpenBanner() {
        LinearLayout banner = new LinearLayout(this);
        banner.setOrientation(LinearLayout.VERTICAL);
        banner.setPadding(dp(16), dp(14), dp(16), dp(14));
        setRoundedBg(banner, 0xFF1A1A2E, 16);

        LinearLayout inner = new LinearLayout(this);
        inner.setOrientation(LinearLayout.HORIZONTAL);
        inner.setGravity(Gravity.CENTER_VERTICAL);

        View accent = new View(this);
        accent.setBackgroundColor(ORANGE_WARN);
        LinearLayout.LayoutParams accentLp = new LinearLayout.LayoutParams(dp(4),
            LinearLayout.LayoutParams.MATCH_PARENT);
        accentLp.setMargins(0, 0, dp(12), 0);
        inner.addView(accent, accentLp);

        LinearLayout textArea = new LinearLayout(this);
        textArea.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams taLp = new LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        inner.addView(textArea, taLp);

        TextView bannerTitle = new TextView(this);
        bannerTitle.setText("Android Freedom at Risk!");
        bannerTitle.setTextSize(13f);
        bannerTitle.setTextColor(ORANGE_WARN);
        bannerTitle.setTypeface(Typeface.DEFAULT_BOLD);
        textArea.addView(bannerTitle);

        TextView bannerMsg = new TextView(this);
        bannerMsg.setText("Android is becoming a locked-down platform. " +
            "Sideloading and open source apps are under threat.");
        bannerMsg.setTextSize(11f);
        bannerMsg.setTextColor(TEXT_SEC);
        bannerMsg.setPadding(0, dp(4), 0, dp(8));
        textArea.addView(bannerMsg);

        TextView learnMore = new TextView(this);
        learnMore.setText("Learn more and take action \u2192");
        learnMore.setTextSize(11f);
        learnMore.setTextColor(TEAL_PRIMARY);
        learnMore.setTypeface(Typeface.DEFAULT_BOLD);
        learnMore.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Intent intent = new Intent(Intent.ACTION_VIEW,
                    Uri.parse("https://keepandroidopen.org/sq/"));
                startActivity(intent);
            }
        });
        textArea.addView(learnMore);
        banner.addView(inner);
        return banner;
    }

    private LinearLayout buildImportanceSection() {
        LinearLayout section = new LinearLayout(this);
        section.setOrientation(LinearLayout.VERTICAL);

        addImportanceCard(section, "What is Root?",
            "Rooting gives you full administrator access to your Android device. " +
            "It allows you to modify system files, remove pre-installed apps, " +
            "and install powerful tools that require deep system access.",
            TEAL_PRIMARY, false);
        section.addView(spacer(8));

        addImportanceCard(section, "Benefits of Root",
            "- Full control over your device\n" +
            "- Remove bloatware and ads system-wide\n" +
            "- Advanced backup and restore\n" +
            "- Custom ROMs and kernels\n" +
            "- Better performance tweaks\n" +
            "- Advanced firewall and privacy tools",
            GREEN_PASS, false);
        section.addView(spacer(8));

        addImportanceCard(section, "Risks of Root",
            "- Security vulnerabilities if misused\n" +
            "- Malicious apps can gain full system access\n" +
            "- May void your device warranty\n" +
            "- Risk of bricking your device\n" +
            "- Banking and payment apps may not work\n" +
            "- OTA updates may fail",
            RED_FAIL, true);
        section.addView(spacer(8));

        addImportanceCard(section, "Safety Tips",
            "- Only grant root to apps you trust\n" +
            "- Use Magisk for systemless root\n" +
            "- Keep your device updated\n" +
            "- Use a root firewall to control access\n" +
            "- Regularly audit which apps have root",
            ORANGE_WARN, false);

        return section;
    }

    private void addImportanceCard(LinearLayout parent, String title,
            String content, int accentColor, boolean isWarning) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        setRoundedBg(card, BG_CARD, 14);

        LinearLayout titleRow = new LinearLayout(this);
        titleRow.setOrientation(LinearLayout.HORIZONTAL);
        titleRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView dot = new TextView(this);
        dot.setText("\u25cf  ");
        dot.setTextColor(accentColor);
        dot.setTextSize(12f);
        titleRow.addView(dot);

        TextView titleView = new TextView(this);
        titleView.setText(title);
        titleView.setTextColor(accentColor);
        titleView.setTextSize(14f);
        titleView.setTypeface(Typeface.DEFAULT_BOLD);
        titleRow.addView(titleView);
        card.addView(titleRow);

        View div = new View(this);
        div.setBackgroundColor(0xFF1E2F3D);
        LinearLayout.LayoutParams divLp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
        divLp.setMargins(0, dp(8), 0, dp(8));
        card.addView(div, divLp);

        TextView contentView = new TextView(this);
        contentView.setText(content);
        contentView.setTextColor(TEXT_SEC);
        contentView.setTextSize(12f);
        contentView.setLineSpacing(dp(3), 1f);
        card.addView(contentView);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        parent.addView(card, lp);
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

        TextView dot = new TextView(this);
        dot.setText(" \u25cf ");
        dot.setTextSize(10f);
        dot.setTextColor(item.isWarning ? ORANGE_WARN : TEAL_PRIMARY);
        card.addView(dot);

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
        summarySubtitle.setText("Running all checks on your device");
        summarySubtitle.setTextColor(TEXT_SEC);
        scoreText.setText("");

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
                final int score = detector.calculateRiskScore(checks);
                mainHandler.post(new Runnable() {
                    public void run() {
                        progressContainer.setVisibility(View.GONE);
                        scanButton.setEnabled(true);
                        setRoundedBg(scanButton, TEAL_PRIMARY, 50);
                        scanButton.setText("SCAN AGAIN");
                        updateSummary(detected, total, score);
                        saveHistory(detected, total, score);
                        loadHistory();
                    }
                });
            }
        });
        t.start();
    }

    private void addResultRow(final RootDetector.CheckResult check) {
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

        // Info icon for explanation
        TextView infoIcon = new TextView(this);
        infoIcon.setText(" ? ");
        infoIcon.setTextSize(12f);
        infoIcon.setTextColor(TEAL_PRIMARY);
        infoIcon.setTypeface(Typeface.DEFAULT_BOLD);
        card.addView(infoIcon);

        // Click to show explanation
        card.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showExplanation(check);
            }
        });

        AlphaAnimation anim = new AlphaAnimation(0f, 1f);
        anim.setDuration(200);
        card.startAnimation(anim);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, dp(8));
        resultsLayout.addView(card, lp);
    }

    private void showExplanation(RootDetector.CheckResult check) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(check.name);
        builder.setMessage(
            "Status: " + (check.detected ? "DETECTED" : "NOT DETECTED") + "\n\n" +
            "Detail: " + check.detail + "\n\n" +
            "What this means:\n" + check.explanation
        );
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
            }
        });
        builder.show();
    }

    private void updateSummary(int detected, int total, int score) {
        ScaleAnimation scale = new ScaleAnimation(
            0.95f, 1f, 0.95f, 1f,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f);
        scale.setDuration(300);
        summaryCard.startAnimation(scale);

        scoreText.setText(score + "/100");

        if (detected == 0) {
            setRoundedBg(summaryCard, 0xFF0D2B1A, 24);
            summaryTitle.setText("Device is Clean");
            summaryTitle.setTextColor(GREEN_PASS);
            summarySubtitle.setText("All "+total+" checks passed");
            summarySubtitle.setTextColor(0xFF81C784);
            scoreText.setTextColor(GREEN_PASS);
        } else if (detected <= 3) {
            setRoundedBg(summaryCard, 0xFF2B1F0D, 24);
            summaryTitle.setText("Possible Root");
            summaryTitle.setTextColor(ORANGE_WARN);
            summarySubtitle.setText(detected+" of "+total+" checks flagged");
            summarySubtitle.setTextColor(0xFFFFCC80);
            scoreText.setTextColor(ORANGE_WARN);
        } else {
            setRoundedBg(summaryCard, 0xFF2B0D0D, 24);
            summaryTitle.setText("Root Detected!");
            summaryTitle.setTextColor(RED_FAIL);
            summarySubtitle.setText(detected+" of "+total+" checks flagged");
            summarySubtitle.setTextColor(0xFFEF9A9A);
            scoreText.setTextColor(RED_FAIL);
        }
    }

    @Override
    public void onBackPressed() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Thanks for using Advanced Root Checker!");
        builder.setMessage(
            "If you like this app please share my " +
            "GitHub project with your friends and family!\n\n" +
            "github.com/Laert-Android/Advanced-Root-Checker\n\n" +
            "Have a good day!");
        builder.setPositiveButton("Share", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                Intent shareIntent = new Intent(Intent.ACTION_SEND);
                shareIntent.setType("text/plain");
                shareIntent.putExtra(Intent.EXTRA_SUBJECT, "Advanced Root Checker");
                shareIntent.putExtra(Intent.EXTRA_TEXT,
                    "Check out Advanced Root Checker - free open source " +
                    "root detection app for Android!\n\n" +
                    "https://github.com/Laert-Android/Advanced-Root-Checker\n\n" +
                    "No ads. No tracking. Fully open source!");
                startActivity(Intent.createChooser(shareIntent, "Share via"));
            }
        });
        builder.setNegativeButton("Close App", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                finish();
            }
        });
        builder.setCancelable(false);
        builder.show();
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
