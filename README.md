# Aegis: phone security & privacy scanner

An Android app that checks your phone for spy apps, malware, hidden access, traffic interception and weak security settings. It runs entirely on the phone. **Works on any Android 8.0 or newer phone, no root needed.**

## What it checks

**Scan tab** (fully offline)
- **Known spy apps & malware:** package names, signing certificates (SHA-1 and SHA-256) and app-file fingerprints merged from three sources: stalkerware-indicators, AndroDR's rules (banking trojans, spyware) and MVT's government-spyware indicators (Pegasus, Predator, NoviSpy and others).
- **Bootloader & Verified Boot (hardware check):** asks the phone's security chip, through key attestation checked against Google's root key, whether the bootloader is locked. A modified Android can't fake this the way it can hide root files.
- **Advanced Protection (Android 16+):** shows whether it's on and how to turn it on.
- **When flagged apps last ran:** if you allow Usage access, each flagged app shows when it was last opened and last ran in the background.
- **Hidden access:** apps with Accessibility (screen reading/control), Device admin, or Notification access.
- **Suspicious apps:** a score combining install source (store or not), hidden icon, SMS/call-log/always-on location access, auto-start + microphone, system-sounding names.
- **Interception:** user-installed security certificates, proxy, active VPN.
- **Phone security:** screen lock, security-patch age, encryption, USB/wireless debugging, signs of rooting.
- **Changes since last scan:** new apps and new hidden access since the previous scan.
- **Permission overview:** which apps can track location all the time, read SMS, use mic/camera.

Every finding is rated **Act now / Review / Good to know / All good**, with buttons to open the right settings page, app info, or uninstall. Apps you know are fine can be marked "I trust this app".

**Tools tab** (uses the internet only when you tap)
- **Trackers inside your apps:** finds Facebook, Google, AppsFlyer and other tracking code (Exodus Privacy method).
- **Password leak check:** Have I Been Pwned. Only 5 characters of a hash leave the phone.
- **Scam message checker:** paste an SMS/WhatsApp message. Spots fake KYC, OTP and UPI-PIN requests, "digital arrest", electricity cut-off, parcel, prize, job and loan scams (English and Hinglish), checks every link inside, and offers **Report to Chakshu** (Sanchar Saathi) and **Call 1930**. Offline.
- **Link checker:** fake bank/UPI/government sites, look-alike letters, hidden short links, spy-app and government-spyware sites, and offline phishing blocklists (OpenPhish/PhishTank via malware-filter; Phishing Army after an update), plus URLhaus with a free key.
- **Real mic/camera/location use (optional, Shizuku):** with the free Shizuku app (started via Wireless debugging, no root), reads Android's own record of when each app last used the mic, camera, location, SMS, contacts or clipboard.
- **Malware database check:** compares every app with MalwareBazaar (free abuse.ch key).
- **Update databases:** newest spy-app lists (all three sources), phishing lists and the Exodus tracker list. Everything also ships inside the app, so it works offline from the first launch.

**Privacy tab:** call-forwarding check (`*#21#`), Google security check-up, signed-in devices, removing your details from Google Search, auto-deleting history, WhatsApp/Instagram sessions, Xiaomi ad settings, and where to get help (1930 / cybercrime.gov.in).

## Get the APK (no Android Studio needed)

GitHub builds the app for you for free:

1. Sign in at **github.com** and create a new repository (the **+** at the top right → *New repository*). Name it `Aegis`. **Private** is fine.
2. On the empty repository page, click **uploading an existing file**. Unzip `Aegis.zip` on your computer, then drag **everything inside the `Aegis` folder** (including the hidden `.github` folder) into the page and click **Commit changes**.
   - On Mac, press `Cmd + Shift + .` in Finder to show hidden folders. On Windows: View → Show → Hidden items.
3. Open the **Actions** tab. A build named "Build APK" starts automatically (about 3–5 minutes).
4. When it shows a green tick, click it and download **Aegis-APK** at the bottom. Unzip it to get `Aegis.apk`.
5. Copy `Aegis.apk` to your phone and open it. Android will ask to allow installing from this source. Allow it, install, then switch that permission off again.

On Xiaomi phones, if installation is blocked: Settings → Apps → Manage apps → ⋮ → Settings → turn off **"Security scan"** for app installs, install, then turn it back on. Google Play Protect may also warn that the app is unknown. That's expected for an app you built yourself. Tap **More details → Install anyway**.

### Or build with Android Studio
Open the `Aegis` folder in Android Studio, wait for the sync, then press Run with your phone connected.

## Limits

- A clean result means no *known* spy app or warning sign was found. Advanced, targeted spyware (like Pegasus) can hide from any app. For that, see the Mobile Verification Toolkit (MVT) on a computer.
- Android doesn't let normal apps see the exact history of when other apps used the mic, camera or location. The scan shows which apps are *allowed* to use them; the optional Shizuku check shows actual use.
- The scam message checker uses word patterns, not AI. New scam wording can slip past it.
- Debloating Xiaomi system apps needs a computer (ADB) and isn't included.

## Data sources & credits
Bundled copies are in `app/src/main/assets/`.
- [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) (CC BY 4.0): `ioc.yaml`, `samples.csv`.
- [android-sigma-rules/rules](https://github.com/android-sigma-rules/rules) ioc-data, used by AndroDR (CC BY 4.0): `androdr_*.yml`.
- [MVT indicators](https://github.com/mvt-project/mvt-indicators) (Amnesty International, Citizen Lab and others), converted to `mvt_iocs.tsv`.
- [Exodus Privacy](https://exodus-privacy.eu.org) tracker signatures (ODbL 1.0), via the android-sigma-rules mirror: `trackers.yml`. Exodus asks end-user apps not to call its API, so the app doesn't.
- [malware-filter phishing-filter](https://gitlab.com/malware-filter/phishing-filter) (CC BY-SA 4.0; OpenPhish, PhishTank): `phishing_domains.txt`. [Phishing Army](https://phishing.army) is downloaded on update only.
- [Shizuku](https://github.com/RikkaApps/Shizuku) (Apache-2.0), optional.
- [abuse.ch](https://abuse.ch) MalwareBazaar & URLhaus.
- [Have I Been Pwned](https://haveibeenpwned.com) Pwned Passwords.

For personal use.
