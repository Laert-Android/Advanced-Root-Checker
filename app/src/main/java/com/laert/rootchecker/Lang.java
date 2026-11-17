package com.laert.rootchecker;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class Lang {

    private static final String PREFS = "settings";
    private static final String KEY = "lang";
    private static boolean sq = false;

    private static final Map<String, String> SQ = new HashMap<String, String>();
    private static final String[][] PHRASES = new String[][] {
        {"Could not determine (", "Nuk u përcaktua ("},
        {"Kernel build year ", "Viti i build-it të kernel-it "},
        {", security patch date unavailable", ", data e përditësimit të sigurisë nuk ka"},
        {" vs security patch year ", " kundrejt vitit të përditësimit të sigurisë "},
        {" consistent with patch year ", " në përputhje me vitin e përditësimit "},
        {"Found at: ", "U gjet në: "},
        {"Found in: ", "U gjet në: "},
        {"Found: ", "U gjet: "},
        {"Detected: ", "U zbulua: "},
        {" suspicious path(s) found. First: ", " rrugë të dyshimta u gjetën. I pari: "},
        {" module(s) installed", " module të instaluara"},
        {"Signed with test-keys: ", "Nënshkruar me test-keys: "},
        {"Tags: ", "Etiketat: "},
        {"Mounted as: ", "Montuar si: "},
        {"Build type: ", "Lloji i build-it: "},
        {"Local signals suggest FAIL: ", "Sinjalet lokale sugjerojnë DËSHTIM: "},
        {"Hardware: ", "Harduer: "},
        {"Model: ", "Modeli: "},
        {"USB config: ", "Konfigurimi USB: "},
        {"Zygisk module: ", "Moduli Zygisk: "},
        {"State: ", "Gjendja: "},
        {"Knox warranty void: ", "Garancia Knox është hequr: "},
        {"Knox fuse: ", "Siguresa Knox: "},
        {"AVB version: ", "Versioni AVB: "},
        {"MISMATCH (read from disk, bypasses PackageManager) - got ", "PA PËRPUTHJE (lexuar nga disku, anashkalon PackageManager) - u mor "},
        {"MISMATCH - expected ", "PA PËRPUTHJE - pritej "},
        {"... got ", "... u mor "},
        {"Signature verified (matches ", "Firma u verifikua (përputhet me "},
        {"Verified directly from APK file bytes (matches ", "U verifikua drejtpërdrejt nga bajtet e APK (përputhet me "},
        {"Could not parse certificate from ", "Nuk u analizua certifikata nga "},
        {"Package name mismatch: ", "Emri i paketës nuk përputhet: "},
        {"Hook found: ", "Hook u gjet: "},
        {"Detected class: ", "Klasa e zbuluar: "},
        {"Suspicious ClassLoader: ", "ClassLoader i dyshimtë: "},
        {"Suspicious: ", "I dyshimtë: "},
        {"Frida server detected on port ", "Serveri Frida u zbulua në portën "},
        {"Data directory looks virtualized: ", "Direktoria e të dhënave duket e virtualizuar: "},
        {" suspicious mount(s), e.g.: ", " mount i dyshimtë, p.sh.: "},
        {" - legitimate developer tools, not treated as root evidence", " - mjete legjitime zhvilluesish, nuk trajtohen si provë root"},
        {"Error: ", "Gabim: "},
        {"Scanning... ", "Duke skanuar... "},
        {" flags | Score: ", " flamuj | Rezultati: "},
        {"All checks run locally. No data sent anywhere.", "Të gjitha kontrollet ekzekutohen lokalisht. Asnjë e dhënë nuk dërgohet askund."},
        {"Tracer PID: ", "PID i gjurmuesit: "},
    };

    static {
        SQ.put("Compares the kernel build date against the claimed security patch level. A large gap can indicate a re-flashed or custom kernel, but isn't conclusive on its own - some OEMs legitimately keep older kernel builds.", "Krahason datën e build-it të kernel-it me nivelin e deklaruar të përditësimit të sigurisë. Një hendek i madh mund të tregojë kernel të ri-flashuar ose i modifkuar, por nuk është përfundimtar vetëm - disa prodhues mbajnë legjitimisht kernel më të vjetër.");
        SQ.put("Kernel Freshness", "Freskia e Kernel-it");
        SQ.put("Could not read /proc/version", "Nuk u lexua /proc/version");
        SQ.put("No date found in /proc/version", "Nuk u gjet datë në /proc/version");
        SQ.put("Could not determine", "Nuk u përcaktua");
        SQ.put("Generates a test key in the Android Keystore and checks whether the OS actually placed it in secure hardware (TEE/StrongBox). A software-only key on a device that should have hardware security is a strong tamper signal.", "Gjeneron një çelës testimi në Android Keystore dhe kontrollon nëse sistemi e vendosi realisht në harduer të sigurt (TEE/StrongBox). Një çelës vetëm-softuer në një pajisje që duhet të ketë siguri harduerike është sinjal i fortë ndërhyrjeje.");
        SQ.put("Hardware Key Attestation", "Atestimi i Çelësit Harduerik");
        SQ.put("Requires Android 6.0+", "Kërkon Android 6.0+");
        SQ.put("Keys are NOT hardware-backed (software emulated)", "Çelësat NUK mbështeten nga hardueri (emuluar me softuer)");
        SQ.put("Keys are hardware-backed (TEE/StrongBox)", "Çelësat mbështeten nga hardueri (TEE/StrongBox)");
        SQ.put("SuperUser Binary", "Skedari Binar SuperUser");
        SQ.put("The 'su' binary grants superuser access. Its presence strongly indicates root.", "Skedari 'su' jep qasje superuser. Prania e tij tregon fuqishëm root.");
        SQ.put("Not found in common paths", "Nuk u gjet në shtigjet e zakonshme");
        SQ.put("su in PATH", "su në PATH");
        SQ.put("If 'su' is in PATH, any app can easily request root access.", "Nëse 'su' është në PATH, çdo aplikacion mund të kërkojë lehtë qasje root.");
        SQ.put("Not found in PATH", "Nuk u gjet në PATH");
        SQ.put("System Path Scan", "Skanimi i Shtigjeve të Sistemit");
        SQ.put("Scans 90+ system paths for root artifacts including su binaries, Magisk, KernelSU, APatch, Xposed and more.", "Skanon mbi 90 shtigje sistemi për gjurmë root, përfshirë skedarë su, Magisk, KernelSU, APatch, Xposed e të tjera.");
        SQ.put("No suspicious paths found (90+ paths checked)", "Nuk u gjetën shtigje të dyshimta (u kontrolluan mbi 90 shtigje)");
        SQ.put("BusyBox Binary", "Skedari Binar BusyBox");
        SQ.put("BusyBox provides Unix tools often installed alongside root. Indicates root access.", "BusyBox ofron mjete Unix që shpesh instalohen bashkë me root. Tregon qasje root.");
        SQ.put("Not present", "Nuk është i pranishëm");
        SQ.put("SuperUser Exists", "SuperUser Ekziston");
        SQ.put("SuperUser/SuperSU APK in system partition confirms the device is rooted.", "APK-ja SuperUser/SuperSU në ndarjen e sistemit konfirmon se pajisja ka root.");
        SQ.put("Not in system", "Nuk është në sistem");
        SQ.put("Magisk is the most popular root solution. It provides systemless root and module support.", "Magisk është zgjidhja më e njohur e root. Ofron root pa ndryshuar sistemin (systemless) dhe mbështetje për module.");
        SQ.put("No Magisk artifacts found", "Nuk u gjetën gjurmë Magisk");
        SQ.put("Zygisk runs code in every app process. Used for advanced root hiding and modules.", "Zygisk ekzekuton kod në çdo proces aplikacioni. Përdoret për fshehje të avancuar të root dhe module.");
        SQ.put("Not detected", "Nuk u zbulua");
        SQ.put("Magisk Modules", "Modulet Magisk");
        SQ.put("Magisk modules modify system behavior. Their presence confirms Magisk is installed.", "Modulet Magisk ndryshojnë sjelljen e sistemit. Prania e tyre konfirmon se Magisk është i instaluar.");
        SQ.put("No modules found", "Nuk u gjetën module");
        SQ.put("Root Management Apps", "Aplikacionet e Menaxhimit të Root");
        SQ.put("Root management apps control which apps get root access on your device.", "Aplikacionet e menaxhimit të root kontrollojnë cilat aplikacione marrin qasje root në pajisjen tënde.");
        SQ.put("None detected", "Asnjë i zbuluar");
        SQ.put("Potentially Dangerous Apps", "Aplikacione Potencialisht të Rrezikshme");
        SQ.put("Apps like Lucky Patcher can bypass in-app purchases and modify other apps.", "Aplikacione si Lucky Patcher mund të anashkalojnë blerjet brenda aplikacionit dhe të modifikojnë aplikacione të tjera.");
        SQ.put("Root Cloaking Apps", "Aplikacione që Fshehin Root");
        SQ.put("Root cloaking apps hide root from other apps like banking apps and game anti-cheat.", "Aplikacionet që fshehin root e fshehin atë nga aplikacione të tjera si ato bankare dhe anti-cheat i lojërave.");
        SQ.put("Shamiko/MagiskHide detected", "Shamiko/MagiskHide u zbulua");
        SQ.put("Test Keys", "Çelësat e Testimit");
        SQ.put("Official Android builds use release-keys. Test-keys indicate a custom or rooted build.", "Build-et zyrtare Android përdorin release-keys. Test-keys tregojnë një build të personalizuar ose me root.");
        SQ.put("Fingerprint Check", "Kontrolli i Gjurmës së Build-it");
        SQ.put("The build fingerprint identifies the exact software on your device. Anomalies suggest modification.", "Gjurma e build-it identifikon saktësisht softuerin në pajisjen tënde. Anomalitë sugjerojnë modifikim.");
        SQ.put("Dangerous Props", "Veti të Rrezikshme");
        SQ.put("System properties like ro.debuggable=1 indicate a debug build that is easier to exploit.", "Vetitë e sistemit si ro.debuggable=1 tregojnë një build debug që shfrytëzohet më lehtë.");
        SQ.put("Could not determine (restricted on this Android version)", "Nuk u përcaktua (i kufizuar në këtë version Android)");
        SQ.put("No dangerous system properties", "Nuk ka veti të rrezikshme sistemi");
        SQ.put("Read/Write Paths", "Shtigje Lexim/Shkrim");
        SQ.put("The /system partition should be read-only. If writable, system files can be modified.", "Ndarja /system duhet të jetë vetëm për lexim. Nëse mund të shkruhet, skedarët e sistemit mund të modifikohen.");
        SQ.put("Could not determine (likely read-only)", "Nuk u përcaktua (ndoshta vetëm lexim)");
        SQ.put("SELinux Status", "Statusi i SELinux");
        SQ.put("SELinux enforces security policies. Permissive mode disables these protections.", "SELinux zbaton politikat e sigurisë. Modaliteti permissive i çaktivizon këto mbrojtje.");
        SQ.put("Could not read enforce file", "Nuk u lexua skedari enforce");
        SQ.put("Root Native Test", "Testi Nativ i Root");
        SQ.put("This test actually executes su to check if root commands work on this device. On a device with Magisk or similar, this may show a one-time root grant prompt.", "Ky test ekzekuton realisht su për të parë nëse komandat root funksionojnë në këtë pajisje. Në një pajisje me Magisk ose të ngjashme, mund të shfaqet një kërkesë njëherëshe për leje root.");
        SQ.put("su command failed or denied", "Komanda su dështoi ose u refuzua");
        SQ.put("Writable /system", "/system i Shkrueshëm");
        SQ.put("Being able to write to /system means system files can be permanently modified.", "Mundësia për të shkruar në /system do të thotë se skedarët e sistemit mund të modifikohen përgjithmonë.");
        SQ.put("Hidden su Binaries", "Skedarë su të Fshehur");
        SQ.put("Some root methods hide su in unusual locations to avoid detection.", "Disa metoda root e fshehin su në vende të pazakonta për të shmangur zbulimin.");
        SQ.put("None found", "Asnjë i gjetur");
        SQ.put("Xposed can hook and modify any app. It requires root and significantly reduces security.", "Xposed mund të lidhet (hook) dhe të modifikojë çdo aplikacion. Kërkon root dhe ul ndjeshëm sigurinë.");
        SQ.put("Found in stack trace", "U gjet në stack trace");
        SQ.put("test-keys build", "build me test-keys");
        SQ.put("Generic fingerprint", "Gjurmë gjenerike");
        SQ.put("Magisk detected", "Magisk u zbulua");
        SQ.put("Play Integrity Heuristics (Offline)", "Heuristikat e Play Integrity (Offline)");
        SQ.put("No local red flags found", "Nuk u gjetën sinjale alarmi lokale");
        SQ.put("This is NOT a real Play Integrity API verdict. The real Play Integrity API requires an internet connection to verify with Google's servers, which this app intentionally does not use. This check only approximates the result using local build signals (test-keys, build type, fingerprint, Magisk presence) and can be wrong in either direction.", "Ky NUK është një verdikt i vërtetë i Play Integrity API. Play Integrity API i vërtetë kërkon internet për verifikim me serverat e Google, që ky aplikacion nuk i përdor qëllimisht. Ky kontroll vetëm përafron rezultatin me sinjale lokale të build-it (test-keys, lloji i build-it, gjurma, prania e Magisk) dhe mund të gabojë në të dyja drejtimet.");
        SQ.put("Real device detected", "U zbulua pajisje reale");
        SQ.put("QEMU socket found", "U gjet socket QEMU");
        SQ.put("Emulator Detection", "Zbulimi i Emulatorit");
        SQ.put("Running on an emulator may indicate automated testing or analysis of your device.", "Ekzekutimi në emulator mund të tregojë testim të automatizuar ose analizë të pajisjes.");
        SQ.put("ADB Status", "Statusi i ADB");
        SQ.put("ADB allows full device access from a computer. Should be disabled for security.", "ADB lejon qasje të plotë në pajisje nga një kompjuter. Duhet çaktivizuar për siguri.");
        SQ.put("ADB is enabled", "ADB është aktiv");
        SQ.put("ADB not enabled via prop", "ADB nuk është aktiv nga vetia");
        SQ.put("Developer Options", "Opsionet e Zhvilluesit");
        SQ.put("Developer options enable debugging features that can be used to access device data.", "Opsionet e zhvilluesit aktivizojnë veçori debug që mund të përdoren për të aksesuar të dhënat e pajisjes.");
        SQ.put("ADB not in USB config", "ADB nuk është në konfigurimin USB");
        SQ.put("OTA Updates", "Përditësimet OTA");
        SQ.put("OTA updates deliver important security patches. Keeping them enabled is recommended.", "Përditësimet OTA sjellin përditësime të rëndësishme sigurie. Rekomandohet t'i mbash aktive.");
        SQ.put("OTA updates disabled", "Përditësimet OTA janë çaktivizuar");
        SQ.put("Disabled OTA updates means the device cannot receive security patches automatically.", "Përditësimet OTA të çaktivizuara do të thotë se pajisja nuk merr automatikisht përditësime sigurie.");
        SQ.put("OTA updates enabled", "Përditësimet OTA janë aktive");
        SQ.put("DenyList enabled", "DenyList është aktive");
        SQ.put("DenyList hides root from specific apps. Indicates active root hiding attempts.", "DenyList e fsheh root nga aplikacione të caktuara. Tregon përpjekje aktive për fshehje të root.");
        SQ.put("Zygisk Modules", "Modulet Zygisk");
        SQ.put("Zygisk modules inject code into apps and can bypass security checks.", "Modulet Zygisk injektojnë kod në aplikacione dhe mund të anashkalojnë kontrollet e sigurisë.");
        SQ.put("No Zygisk modules found", "Nuk u gjetën module Zygisk");
        SQ.put("KernelSU provides root at the kernel level, making it harder to detect than Magisk.", "KernelSU ofron root në nivel kernel-i, duke e bërë më të vështirë për t'u zbuluar se Magisk.");
        SQ.put("APatch is a kernel-based root solution similar to KernelSU.", "APatch është një zgjidhje root në nivel kernel-i e ngjashme me KernelSU.");
        SQ.put("Verified Boot ensures the OS hasn't been tampered with. Orange/Red means modified.", "Verified Boot siguron që sistemi nuk është ndryshuar. Portokalli/Kuq do të thotë i modifikuar.");
        SQ.put("Knox Status", "Statusi i Knox");
        SQ.put("Samsung Knox warranty bit is tripped when root is attempted. Cannot be reset.", "Biti i garancisë Samsung Knox aktivizohet kur provohet root. Nuk mund të rivendoset.");
        SQ.put("Knox not tripped or not Samsung", "Knox nuk është aktivizuar ose nuk është Samsung");
        SQ.put("Anti-Rollback Protection", "Mbrojtja Anti-Rollback");
        SQ.put("Anti-rollback protection prevents downgrading to vulnerable older OS versions.", "Mbrojtja anti-rollback pengon kthimin në versione të vjetra të cenueshme të sistemit.");
        SQ.put("Treble Support", "Mbështetja Treble");
        SQ.put("Project Treble separates vendor implementation from Android OS for faster updates.", "Project Treble ndan implementimin e prodhuesit nga sistemi Android për përditësime më të shpejta.");
        SQ.put("Project Treble enabled", "Project Treble është aktiv");
        SQ.put("Treble not enabled", "Treble nuk është aktiv");
        SQ.put("Native Capability Check", "Kontrolli i Aftësive Native");
        SQ.put("Checks Linux capabilities directly. CAP_CHOWN set indicates root-level privileges.", "Kontrollon drejtpërdrejt aftësitë Linux. CAP_CHOWN i vendosur tregon privilegje në nivel root.");
        SQ.put("Could not read capabilities", "Nuk u lexuan aftësitë");
        SQ.put("APK Signature", "Firma e APK");
        SQ.put("No signatures found", "Nuk u gjetën firma");
        SQ.put("Xposed is hooking this app: ", "Xposed po e lidh (hook) këtë aplikacion: ");
        SQ.put("XposedBridge class found", "U gjet klasa XposedBridge");
        SQ.put("XposedHelpers class found", "U gjet klasa XposedHelpers");
        SQ.put("Xposed Hook", "Hook Xposed");
        SQ.put("Xposed Hook Detected", "Hook Xposed u zbulua");
        SQ.put("Frida Detected", "Frida u zbulua");
        SQ.put("Found in process maps", "U gjet në hartat e procesit");
        SQ.put("Frida Hook", "Hook Frida");
        SQ.put("Suspicious Library", "Librari e Dyshimtë");
        SQ.put("Suspicious Libraries", "Libraritë e Dyshimta");
        SQ.put("Stack Trace Hook", "Hook në Stack Trace");
        SQ.put("No hooks detected", "Nuk u zbuluan hook-e");
        SQ.put("Raw APK Signature", "Firma e Papërpunuar e APK");
        SQ.put("No V1 (JAR) signature block found in APK file", "Nuk u gjet bllok firme V1 (JAR) në skedarin APK");
        SQ.put("Package Name", "Emri i Paketës");
        SQ.put("Debugger detected", "Debugger u zbulua");
        SQ.put("No debugger", "Pa debugger");
        SQ.put("Process Trace", "Gjurmimi i Procesit");
        SQ.put("No tracing detected", "Nuk u zbulua gjurmim");
        SQ.put("Hooking Framework", "Framework Hooking");
        SQ.put("Hooking Frameworks", "Framework-e Hooking");
        SQ.put("No Frida ports detected", "Nuk u zbuluan porta Frida");
        SQ.put("Frida Port", "Porta Frida");
        SQ.put("Virtual/Cloned Environment", "Mjedis Virtual/I Klonuar");
        SQ.put("Normal data directory", "Direktori normale e të dhënave");
        SQ.put("Could not read mount namespace", "Nuk u lexua mount namespace");
        SQ.put("No overlay/tmpfs mounts found on /system, /vendor, /product, /apex", "Nuk u gjetën mount-e overlay/tmpfs në /system, /vendor, /product, /apex");
        SQ.put("Power-User Apps", "Aplikacione për Përdorues të Avancuar");
        SQ.put("None of the common developer/power-user tools detected", "Asnjë nga mjetet e zakonshme të zhvilluesve/përdoruesve të avancuar nuk u zbulua");
        SQ.put("Manifest Integrity", "Integriteti i Manifestit");
        SQ.put("Package name modified", "Emri i paketës u ndryshua");
        SQ.put("Application is debuggable", "Aplikacioni është debuggable");
        SQ.put("allowBackup is enabled", "allowBackup është aktiv");
        SQ.put("Verified", "I verifikuar");
        SQ.put("Unknown", "E panjohur");
        SQ.put("Manufacturer", "Prodhuesi");
        SQ.put("Brand", "Marka");
        SQ.put("Model", "Modeli");
        SQ.put("Board", "Pllaka");
        SQ.put("Hardware", "Harduer");
        SQ.put("User @ Host", "Përdoruesi @ Host");
        SQ.put("User", "Përdoruesi");
        SQ.put("Device", "Pajisja");
        SQ.put("Android Version", "Versioni i Android");
        SQ.put("Security Patch", "Përditësimi i Sigurisë");
        SQ.put("Build Type", "Lloji i Build-it");
        SQ.put("Screen Lock", "Kyçja e Ekranit");
        SQ.put("Enabled", "Aktiv");
        SQ.put("Not set", "I pavendosur");
        SQ.put("CPU Architecture", "Arkitektura e CPU");
        SQ.put("Build Fingerprint", "Gjurma e Build-it");
        SQ.put("No Ads  |  No Tracking  |  Open Source", "Pa Reklama  |  Pa Gjurmim  |  Burim i Hapur");
        SQ.put("Ready to Scan", "Gati për Skanim");
        SQ.put("Tap SCAN FOR ROOT to check your device", "Shtyp SKANO PËR ROOT për të kontrolluar pajisjen");
        SQ.put("SCAN FOR ROOT", "SKANO PËR ROOT");
        SQ.put("SCAN HISTORY", "HISTORIKU I SKANIMEVE");
        SQ.put("CHECK RESULTS", "REZULTATET E KONTROLLEVE");
        SQ.put("Tap any result to learn more", "Shtyp çdo rezultat për të mësuar më shumë");
        SQ.put("No results yet. Run a scan to see details.", "Ende pa rezultate. Bëj një skanim për të parë detajet.");
        SQ.put("ANTI-TAMPER CHECKS", "KONTROLLET ANTI-NDRYSHIM");
        SQ.put("Checks if this app is being hooked or modified", "Kontrollon nëse ky aplikacion po lidhet (hook) ose po modifikohet");
        SQ.put("Running anti-tamper checks…", "Duke ekzekutuar kontrollet anti-ndryshim…");
        SQ.put("DEVICE SECURITY INFO", "INFO E SIGURISË SË PAJISJES");
        SQ.put("Reading device info…", "Duke lexuar info të pajisjes…");
        SQ.put("IMPORTANCE OF ROOT", "RËNDËSIA E ROOT");
        SQ.put("No previous scans yet.", "Ende pa skanime të mëparshme.");
        SQ.put("Android Freedom at Risk!", "Liria e Android në Rrezik!");
        SQ.put("Android is becoming a locked-down platform. Sideloading and open source apps are under threat.", "Android po kthehet në një platformë të mbyllur. Instalimi i aplikacioneve jashtë dyqanit dhe aplikacionet me burim të hapur janë nën kërcënim.");
        SQ.put("Learn more and take action \u2192", "Mëso më shumë dhe vepro →");
        SQ.put("What is Root?", "Çfarë është Root?");
        SQ.put("Rooting gives you full administrator access to your Android device. It allows you to modify system files, remove pre-installed apps, and install powerful tools that require deep system access.", "Root të jep qasje të plotë administratori në pajisjen tënde Android. Të lejon të modifikosh skedarët e sistemit, të heqësh aplikacionet e para-instaluara dhe të instalosh mjete të fuqishme që kërkojnë qasje të thellë në sistem.");
        SQ.put("Benefits of Root", "Përfitimet e Root");
        SQ.put("- Full control over your device\n- Remove bloatware and ads system-wide\n- Advanced backup and restore\n- Custom ROMs and kernels\n- Better performance tweaks\n- Advanced firewall and privacy tools", "- Kontroll i plotë mbi pajisjen tënde\n- Heq aplikacionet e panevojshme dhe reklamat në të gjithë sistemin\n- Backup dhe rikthim i avancuar\n- ROM dhe kernel të personalizuar\n- Përmirësime më të mira të performancës\n- Mjete të avancuara firewall dhe privatësie");
        SQ.put("Risks of Root", "Rreziqet e Root");
        SQ.put("- Security vulnerabilities if misused\n- Malicious apps can gain full system access\n- May void your device warranty\n- Risk of bricking your device\n- Banking and payment apps may not work\n- OTA updates may fail", "- Cenueshmëri sigurie nëse përdoret keq\n- Aplikacionet keqdashëse mund të marrin qasje të plotë në sistem\n- Mund ta anulojë garancinë e pajisjes\n- Rrezik për ta bërë pajisjen të papërdorshme (brick)\n- Aplikacionet bankare dhe të pagesave mund të mos funksionojnë\n- Përditësimet OTA mund të dështojnë");
        SQ.put("Safety Tips", "Këshilla Sigurie");
        SQ.put("- Only grant root to apps you trust\n- Use Magisk for systemless root\n- Keep your device updated\n- Use a root firewall to control access\n- Regularly audit which apps have root", "- Jep root vetëm aplikacioneve që u beson\n- Përdor Magisk për root pa ndryshuar sistemin\n- Mbaje pajisjen të përditësuar\n- Përdor një firewall root për të kontrolluar qasjen\n- Kontrollo rregullisht cilat aplikacione kanë root");
        SQ.put("SCANNING...", "DUKE SKANUAR...");
        SQ.put("Scanning...", "Duke skanuar...");
        SQ.put("Running all checks on your device", "Duke ekzekutuar të gjitha kontrollet në pajisjen tënde");
        SQ.put("SCAN AGAIN", "SKANO PËRSËRI");
        SQ.put("Device is Clean", "Pajisja është e Pastër");
        SQ.put("Possible Root", "Root i Mundshëm");
        SQ.put("Root Detected!", "Root u Zbulua!");
        SQ.put("Thanks for using Advanced Root Checker!", "Faleminderit që përdor Advanced Root Checker!");
        SQ.put("If you like this app please share my GitHub project with your friends and family!\n\ngithub.com/Laert-Android/Advanced-Root-Checker\n\nHave a good day!", "Nëse të pëlqen ky aplikacion, të lutem ndaje projektin tim në GitHub me miqtë dhe familjen!\n\ngithub.com/Laert-Android/Advanced-Root-Checker\n\nGjithë të mirat!");
        SQ.put("Share", "Ndaj");
        SQ.put("Close App", "Mbyll Aplikacionin");
        SQ.put("Share via", "Ndaj përmes");
        SQ.put("Check out Advanced Root Checker - free open source root detection app for Android!\n\nhttps://github.com/Laert-Android/Advanced-Root-Checker\n\nNo ads. No tracking. Fully open source!", "Shiko Advanced Root Checker - aplikacion falas me burim të hapur për zbulimin e root në Android!\n\nhttps://github.com/Laert-Android/Advanced-Root-Checker\n\nPa reklama. Pa gjurmim. Plotësisht me burim të hapur!");
        SQ.put("PASS", "KALOI");
        SQ.put("FAIL", "DËSHTOI");
        SQ.put("SAFE", "SIGURT");
        SQ.put("WARN", "KUJDES");
        SQ.put("HIGH", "LARTË");
        SQ.put("MEDIUM", "MESME");
        SQ.put("LOW", "ULËT");
        SQ.put("INFO", "INFO");
        SQ.put("DETECTED", "U ZBULUA");
        SQ.put("NOT DETECTED", "NUK U ZBULUA");
        SQ.put("Status: ", "Statusi: ");
        SQ.put("Detail: ", "Detaje: ");
        SQ.put("What this means:\n", "Çfarë do të thotë:\n");
        SQ.put("Settings", "Cilësimet");
        SQ.put("Language", "Gjuha");
        SQ.put("Close", "Mbyll");
        SQ.put("OK", "OK");
        SQ.put("Scanning... %d%%  (%d/%d)", "Duke skanuar... %d%%  (%d/%d)");
        SQ.put("All %d checks passed", "Të gjitha %d kontrollet kaluan");
        SQ.put("%d of %d checks flagged", "%d nga %d kontrolle u shënuan");
    }

    private Lang() {}

    public static void init(Context c) {
        SharedPreferences p = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String l = p.getString(KEY, null);
        if (l == null) {
            l = "sq".equals(Locale.getDefault().getLanguage()) ? "sq" : "en";
        }
        sq = "sq".equals(l);
    }

    public static boolean isSq() {
        return sq;
    }

    public static void set(Context c, boolean albanian) {
        sq = albanian;
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY, albanian ? "sq" : "en").apply();
    }

    public static String t(String en) {
        if (en == null || !sq) return en;
        String r = SQ.get(en);
        if (r != null) return r;
        String out = en;
        for (int i = 0; i < PHRASES.length; i++) {
            if (out.contains(PHRASES[i][0])) {
                out = out.replace(PHRASES[i][0], PHRASES[i][1]);
            }
        }
        return out;
    }

    public static String f(String enFormat, Object... args) {
        return String.format(t(enFormat), args);
    }
}
