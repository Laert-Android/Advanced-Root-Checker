# Advanced Root Checker


![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)


![Version](https://img.shields.io/badge/Version-2.2-teal.svg)

![Android](https://img.shields.io/badge/Android-5.0%2B-green.svg)


A free, open-source Android app that detects root indicators 
on your device. All checks run entirely offline.
No internet permission. No ads. No tracking.

---

## Latest Version: 2.2

### Changelog

**Version 2.2**
- Added Potentially Dangerous Apps detection
- Added Root Cloaking Apps detection (Shamiko, MagiskHide)
- Added Importance of Root section (What is root, Benefits, Risks, Safety Tips)

**Version 2.1**
- Added Device Security Info section
- Shows Android version and security patch level
- Shows SELinux status, bootloader and screen lock
- Shows CPU architecture and kernel version
- Warnings highlighted in orange

**Version 2.0**
- Complete Material You dark teal UI redesign
- Rounded cards with PASS/FAIL pills
- Animated summary card (green/orange/red)
- Progress bar with percentage counter
- Smooth fade-in animations for results
- App name fixed to Advanced Root Checker

**Version 1.0**
- Initial release
- 15 root detection checks

---

## Screenshots



![Main Screen](Screenshots/main_screen.png)




![Results](Screenshots/results_clean.png)



---

## Features

- 17 root detection checks
- Device Security Info section
- Importance of Root educational section
- Material You dark teal design
- PASS/FAIL pills for each check
- Animated results and summary card
- 100% offline - no internet permission
- No ads, no tracking, no analytics
- Open source GPL-3.0

---

## Checks Performed

| Check | Description |
|---|---|
| SuperUser Binary | Looks for su in common paths |
| su in PATH | Checks environment PATH for su |
| BusyBox Binary | Detects BusyBox presence |
| SuperUser Exists | Finds SuperUser/SuperSU APKs |
| Magisk | Detects Magisk directories |
| Root Management Apps | Checks for root manager packages |
| Potentially Dangerous Apps | Detects Lucky Patcher and similar |
| Root Cloaking Apps | Detects Shamiko and MagiskHide |
| Test Keys | Checks build signing keys |
| Fingerprint Check | Analyzes build fingerprint |
| Dangerous Props | Checks system properties |
| Read/Write Paths | Checks /system mount mode |
| SELinux Status | Detects permissive SELinux |
| Root Native Test | Attempts su execution |
| Writable /system | Tests /system write access |
| Hidden su Binaries | Finds hidden su binaries |
| Xposed Framework | Detects Xposed installation |

---

## Build from Source

### Build on Android with Termux (recommended)

**Step 1 - Install Termux from F-Droid (not Play Store)**

**Step 2 - Install dependencies:**
pkg update && pkg upgrade -y

pkg install openjdk-17 git aapt2 wget unzip git apksigner gradle -y

**Step 3 - Set Java path:**
export JAVA_HOME=$PREFIX/lib/jvm/java-17-openjdk

export PATH=$PREFIX/bin:$PATH

**Step 4 - Make it permanent:**
echo 'export JAVA_HOME=$PREFIX/lib/jvm/java-17-openjdk' > ~/.bashrc
echo 'export PATH=PREFIX/bin:HOME/.local/bin:$JAVA_HOME/bin' >> ~/.bashrc
source ~/.bashrc

**Step 5 - Clone the project:**
git clone https://github.com/Laert-Android/Advanced-Root-Checker

cd Advanced-Root-Checker

**Step 6 - Download Android SDK:**
cd ~

wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip

unzip commandlinetools-linux-11076708_latest.zip

mkdir -p ~/android-sdk/cmdline-tools/latest

mv ~/cmdline-tools/* ~/android-sdk/cmdline-tools/latest/


**Step 7 - Set SDK environment:**
echo 'export ANDROID_HOME=$HOME/android-sdk' >> ~/.bashrc
echo 'export PATH=PATH:ANDROID_HOME/cmdline-tools/latest/bin' >> ~/.bashrc
source ~/.bashrc



**Step 8 - Accept licenses and install SDK:**
yes | sdkmanager --licenses

sdkmanager "platforms;android-34" "build-tools;34.0.0"

**Step 9 - Configure project:**
cd ~/Advanced-Root-Checker

gradle wrapper

echo "sdk.dir=$HOME/android-sdk" > local.properties
echo "android.aapt2FromMavenOverride=/data/data/com.termux/files/usr/bin/aapt2" > gradle.properties

**Step 10 - Build the APK:**
./gradlew assembleDebug

**Step 11 - Generate a signing keystore (only needed once):**
keytool -genkey -noprompt 
-keystore ~/my.keystore 
-alias mykey 
-keyalg RSA 
-keysize 2048 
-validity 10000 
-storepass android123 
-keypass android123 
-dname "CN=Dev,OU=Dev,O=Dev,L=City,ST=State,C=US"

**Step 12 - Copy and sign the APK:**
cp app/build/outputs/apk/debug/app-debug.apk ~/RootChecker.apk

apksigner sign 
--ks ~/my.keystore 
--ks-pass pass:android123 
--key-pass pass:android123 
~/RootChecker.apk

**Step 13 - Copy to Downloads and install:**
cp ~/RootChecker.apk /sdcard/Download/RootChecker.apk
Then open your file manager, go to Downloads and tap RootChecker.apk to install.

---

### Notes
- Type the commands one by one to avoid errors
- Steps 1-8 only need to be done once
- For future builds just do Steps 9-13
- If you get SDK location error run Step 9 again
- If you get JAVA_HOME error run Steps 3-4 again
- 
### Build on PC (Windows,Linux)

**Requirements:**
- Java 17 (JDK)
- Android Studio or Android SDK command line tools

**Step 1 - Clone the project:**
git clone https://github.com/Laert-Android/Advanced-Root-Checker
cd Advanced-Root-Checker

**Step 2 - Set your Android SDK path:**
Create a file called local.properties in the root folder:

Windows:
sdk.dir=C\:\\Users\\YourName\\AppData\\Local\\Android\\Sdk

Linux:
sdk.dir=/home/yourname/Android/Sdk

**Step 3 - Build:**
Windows:
gradlew.bat assembleDebug

Linux:
./gradlew assembleDebug

**Step 4 - Find your APK at:**
app/build/outputs/apk/debug/app-debug.apk

**Step 5 - Install on device:**
adb install app/build/outputs/apk/debug/app-debug.apk

---

### Build with Android Studio (easiest on PC)

1. Download Android Studio from developer.android.com
2. Clone the repo or download the zip
3. Open Android Studio
4. Click File -> Open -> select the project folder
5. Wait for Gradle sync to finish
6. Click Run -> Run app
7. Android Studio builds, signs and installs automatically
---

## Privacy

- No internet permission
- No ads or ad SDKs
- No analytics or tracking
- No data collection of any kind
- All checks run locally on device

---

## Download

- [GitHub Releases](https://github.com/Laert-Android/Advanced-Root-Checker/releases)
- F-Droid (coming soon)
- [SourceForge](https://sourceforge.net/projects/advanced-root-checker)

---

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE)
