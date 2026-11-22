package com.ikar.mobile;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.CalendarContract;
import android.view.View;
import android.graphics.Typeface;
import android.widget.*;
import org.json.JSONObject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final int PICK_FILE = 41;
    private static final String API_BASE = "https://ikar-cloudflare-worker-v4gl.vercel.app";
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private LinearLayout root;
    private TextView fileResult, domainResult;
    private EditText domainInput, tokenInput, taskInput;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(24), dp(20), dp(24));
        root.setBackgroundColor(0xFFF3F6FA);
        scroll.addView(root);
        TextView title = label("IKAR", 32, true);
        title.setTextColor(0xFF123B68);
        root.addView(title);
        root.addView(label("Sécurité mobile • Assistant personnel", 14, false));
        addSection("ÉTAT DE PROTECTION");
        addCard(label("Analyse locale : calcul SHA-256 disponible.\nVérification en ligne : nécessite ton jeton API.\nYARA/ClamAV : moteur non intégré pour le moment.", 14, false));
        addSection("ANALYSE LOCALE DE FICHIER");
        addButton("Choisir un fichier et calculer son SHA-256", v -> chooseFile());
        fileResult = label("Aucun fichier analysé. Une empreinte SHA-256 n'est pas un verdict antivirus.", 13, false);
        addCard(fileResult);
        addSection("VÉRIFICATION DE DOMAINE");
        domainInput = input("exemple.com"); root.addView(domainInput);
        tokenInput = input("Jeton API IKAR (saisi ici, non enregistré)");
        tokenInput.setInputType( android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD );
        root.addView(tokenInput);
        addButton("Vérifier avec URLhaus et ThreatFox", v -> checkDomain());
        domainResult = label("Aucune vérification effectuée.", 13, false); addCard(domainResult);
        addSection("ORGANISATION");
        taskInput = input("Ajouter une tâche"); root.addView(taskInput);
        addButton("Enregistrer la tâche sur cet appareil", v -> saveTask());
        addButton("Créer un événement dans le calendrier", v -> openCalendar());
        addButton("Ouvrir un nouveau courriel", v -> openComposer("mailto:"));
        addButton("Ouvrir un nouveau SMS", v -> openComposer("smsto:"));
        addSection("MODULES À CONSTRUIRE");
        module("Assistant IA", "Interface de conversation et connexion serveur à finaliser.");
        module("Protection Web", "Filtrage local des liens et protection de navigation à intégrer.");
        module("YARA / moteur antivirus local", "Base de signatures et moteur Android à intégrer puis tester.");
        module("Protection comportementale", "Analyse avec les API Android autorisées.");
        module("Coffre sécurisé", "Chiffrement local et récupération contrôlée à développer.");
        module("Courriels et messages", "Ouverture des applications choisies ; IKAR ne lit pas les messages privés.");
        root.addView(label("IKAR v0.1.0 — les fonctions non disponibles sont clairement indiquées.", 12, false));
        setContentView(scroll);
    }

    private void chooseFile() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.setType("*/*"); i.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(i, PICK_FILE);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != PICK_FILE || result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData(); fileResult.setText("Calcul SHA-256 en cours…");
        executor.execute(() -> {
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) throw new IOException("Fichier inaccessible");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] buffer = new byte[8192]; int n;
                while ((n = in.read(buffer)) > 0) md.update(buffer, 0, n);
                StringBuilder hash = new StringBuilder();
                for (byte b : md.digest()) hash.append(String.format("%02x", b));
                runOnUiThread(() -> fileResult.setText("SHA-256 :\n" + hash +
                    "\n\nRésultat : empreinte calculée uniquement. Aucune base de signatures ni moteur YARA/ClamAV n'a été exécuté."));
            } catch (Exception e) { runOnUiThread(() -> fileResult.setText("Erreur : " + e.getMessage())); }
        });
    }

    private void checkDomain() {
        String domain = domainInput.getText().toString().trim();
        String token = tokenInput.getText().toString().trim();
        if (domain.isEmpty() || token.isEmpty()) {
            Toast.makeText(this, "Saisis le domaine et ton jeton API.", Toast.LENGTH_LONG).show(); return;
        }
        tokenInput.setText(""); domainResult.setText("Vérification en cours…");
        executor.execute(() -> {
            HttpURLConnection c = null;
            try {
                c = (HttpURLConnection) new URL(API_BASE + "/v1/security/domain-check").openConnection();
                c.setRequestMethod("POST"); c.setConnectTimeout(12000); c.setReadTimeout(15000); c.setDoOutput(true);
                c.setRequestProperty("Authorization", "Bearer " + token);
                c.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                JSONObject body = new JSONObject(); body.put("domain", domain);
                try (OutputStream out = c.getOutputStream()) { out.write(body.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
                int code = c.getResponseCode();
                InputStream stream = code >= 200 && code < 400 ? c.getInputStream() : c.getErrorStream();
                StringBuilder text = new StringBuilder();
                if (stream != null) try (BufferedReader r = new BufferedReader(new InputStreamReader(stream))) {
                    String line; while ((line = r.readLine()) != null) text.append(line).append('\n');
                }
                String output = "HTTP " + code + "\n" + text;
                runOnUiThread(() -> domainResult.setText(output));
            } catch (Exception e) { runOnUiThread(() -> domainResult.setText("Erreur réseau : " + e.getMessage())); }
            finally { if (c != null) c.disconnect(); }
        });
    }

    private void saveTask() {
        String task = taskInput.getText().toString().trim(); if (task.isEmpty()) return;
        String old = getPreferences(MODE_PRIVATE).getString("tasks", "");
        String all = old.isEmpty() ? task : old + "\n" + task;
        getPreferences(MODE_PRIVATE).edit().putString("tasks", all).apply();
        taskInput.setText("");
        addCard(label("Tâches enregistrées :\n" + all, 13, false));
        Toast.makeText(this, "Tâche enregistrée localement.", Toast.LENGTH_SHORT).show();
    }

    private void openCalendar() {
        Intent i = new Intent(Intent.ACTION_INSERT).setData(CalendarContract.Events.CONTENT_URI);
        i.putExtra(CalendarContract.Events.TITLE, "Rappel IKAR");
        try { startActivity(i); } catch (Exception e) { Toast.makeText(this, "Calendrier indisponible.", Toast.LENGTH_SHORT).show(); }
    }
    private void openComposer(String scheme) {
        try { startActivity(Intent.createChooser(new Intent(Intent.ACTION_SENDTO, Uri.parse(scheme)), "Choisir une application")); }
        catch (Exception e) { Toast.makeText(this, "Application indisponible.", Toast.LENGTH_SHORT).show(); }
    }
    private void module(String name, String desc) { addCard(label(name + "\n" + desc + "\nStatut : à développer", 13, false)); }
    private void addSection(String s) {
        TextView t = label(s, 12, true); t.setTextColor(0xFF34516F);
        t.setPadding(0, dp(18), 0, dp(8)); root.addView(t);
    }
    private void addCard(View child) {
        LinearLayout box = new LinearLayout(this); box.setPadding(dp(14), dp(12), dp(14), dp(12));
        box.setBackgroundColor(0xFFFFFFFF); box.addView(child);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2); p.bottomMargin = dp(10); root.addView(box, p);
    }
    private TextView label(String s, int size, boolean bold) {
        TextView t = new TextView(this); t.setText(s); t.setTextSize(size); t.setTextColor(0xFF243447);
        if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD); return t;
    }
    private EditText input(String hint) {
        EditText e = new EditText(this); e.setSingleLine(true); e.setTextSize(14); e.setHint(hint); return e;
    }
    private void addButton(String s, View.OnClickListener action) {
        Button b = new Button(this); b.setText(s); b.setOnClickListener(action); root.addView(b);
    }
    private int dp(int n) { return (int)(n * getResources().getDisplayMetrics().density); }
    @Override protected void onDestroy() { super.onDestroy(); executor.shutdown(); }
}
