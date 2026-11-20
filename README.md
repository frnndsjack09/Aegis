# Aegis: phone security & privacy scanner

An Android app that checks your phone for spy apps, malware, hidden access, traffic interception and weak security settings. It runs entirely on the phone. **Works on any Android 8.0 or newer phone, no root needed.**

## What it checks

**Scan tab** (fully offline)
- **Known spy apps & malware:** package names, signing certificates (SHA-1 and SHA-256) and app-file fingerprints merged from three sources: stalkerware-indicators, AndroDR's rules (banking trojans, spyware) and MVT's government-spyware indicators (Pegasus, Predator, NoviSpy and others).
- **Bootloader & Verified Boot (hardware check):** asks the phone's security chip, through key attestation checked against Google's root key, whether the bootloader is locked. A modified Android can't fake this the way it can hide root files.
- **Advanced Protection (Android 16+):** shows whether it's on and how to turn it on.
- **When flagged apps last ran:** if you allow Usage access, each flagged app shows when it was last opened and last ran in the background.
- **Hidden access:** apps with Accessibility (screen reading/control), Device admin, or Notification access.
- **Suspicious apps:** a score combining install source (store or not), hidden icon, SMS/call-log/always-on location access, auto-start + microphone, system-sounding names, and banking-trojan signs: drawing over other apps (fake login screens) and NFC card reading or card emulation (NFC relay fraud).
- **Fake bank and UPI apps:** apps named like SBI/YONO, HDFC, ICICI, Axis, Kotak, PNB, PhonePe, Paytm, Google Pay, BHIM and others that were installed from a file instead of the Play Store and don't use the official app id, plus app ids from reported fake-bank campaigns. Also checked by new-app alerts and the app-file check.
- **Remote-control apps:** AnyDesk, TeamViewer QuickSupport/Host, RustDesk and AirDroid, plus any app that can both record the screen and tap for you. Marked "Act now" when its Accessibility access is on. Screen-sharing is a common UPI fraud in India.
- **Interception:** user-installed security certificates, proxy, active VPN.
- **Phone security:** screen lock, security-patch age, encryption, USB/wireless debugging, signs of rooting.
- **Changes since last scan:** new apps and new hidden access since the previous scan.
- **Permission overview:** which apps can track location all the time, read SMS, use mic/camera.

Every finding is rated **Act now / Review / Good to know / All good**, with buttons to open the right settings page, app info, or uninstall. Apps you know are fine can be marked "I trust this app".

**Live protection** (Scan tab, both off until you turn them on)
- **New-app alerts:** checks every app you install or update and notifies you right away if it's a known spy app, a remote-control app, or a risky app installed from a file. Background check about every 15 minutes, instant while scam alerts are on. Notification has an Uninstall button.
- **Scam message alerts:** reads new SMS, WhatsApp and Telegram notifications, runs the offline scam checker and link checker, and warns you about scams. Messages are never stored or sent anywhere. Needs Notification access; on Android 13+ sideloaded apps first need App info → ⋮ → Allow restricted settings. Tap the alert to see the full explanation.
- **Share to Aegis:** share any message text to Aegis to check it.
- **Weekly scan:** while new-app alerts are on, Aegis runs a full scan once a week in the background (not on a low battery) and notifies you only if something needs you now.
- **"On a call" warning (opt-in):** if a UPI, bank or screen-sharing app comes to the front while you're on a phone call, Aegis warns you once per app per call (the "bank officer / police / customer care" scam). Uses the Phone permission only to know a call is on, never the number, plus Usage access. Runs inside the scam-alert service, checking every 2 seconds only during calls.
- **Keep protection running:** shows whether battery saver can pause Aegis, with buttons to allow it in the background and (on Xiaomi) open Autostart.

**Phone check-up** (Scan tab, refreshes each time you open Aegis)
- Restart reminder after 3 and 7 days on, age of the last security update, Private DNS (one-tap copy of `dns.adguard-dns.com` to block ads and phishing sites in every app), free storage and the biggest apps (with Usage access), battery temperature and health, free memory, and Xiaomi/Facebook ad and tracking apps that came with the phone, with copyable ADB remove and restore commands.

**Tools tab** (uses the internet only when you tap)
- **Trackers inside your apps:** finds Facebook, Google, AppsFlyer and other tracking code (Exodus Privacy method).
- **Password leak check:** Have I Been Pwned. Only 5 characters of a hash leave the phone.
- **Check a payment QR code:** pick a screenshot or share an image to Aegis. It reads the QR (ZXing, offline) and explains what paying it does: who it pays, the amount, and a scam warning for "receive money / refund / prize" QR codes, since paying a UPI QR always sends money. Website QR codes go through the link checker.
- **Check an app file before installing:** pick an .apk, or tap it in WhatsApp/Files and choose "Open with Aegis". Reads the file without installing it. Flags known malware, fake copies of apps you already have (same app id, different signer), "wedding invitation", "RTO challan", "reward points" and bank-name lures, and risky requests (SMS, Accessibility, notifications, device admin, overlay, NFC). A file signed by the same developer as an installed app is shown as genuine. Offline.
- **Scam message checker:** paste an SMS/WhatsApp message. Spots fake KYC, OTP and UPI-PIN requests, "digital arrest", electricity cut-off, parcel, prize, job and loan scams, wedding-invite and e-challan app files, expiring reward points, stock-tip and "guaranteed returns" investment groups, and call-merge OTP theft (English and Hinglish), checks every link inside, and offers **Report to Chakshu** (Sanchar Saathi) and **Call 1930**. Offline.
- **Link checker:** fake bank/UPI/government sites, look-alike letters, hidden short links, spy-app and government-spyware sites, and offline phishing and malware blocklists (OpenPhish/PhishTank via malware-filter; Phishing Army and HaGeZi Threat Intelligence Feeds after an update), plus URLhaus with a free key.
- **Real mic/camera/location use (optional, Shizuku):** with the free Shizuku app (started via Wireless debugging, no root), reads Android's own record of when each app last used the mic, camera, location, SMS, contacts or clipboard.
- **Malware database check:** compares every app with MalwareBazaar (free abuse.ch key).
- **Update databases:** newest spy-app lists (all three sources), phishing lists and the Exodus tracker list. Everything also ships inside the app, so it works offline from the first launch.

**Privacy tab:** call-forwarding check (`*#21#`), Google security check-up, signed-in devices, removing your details from Google Search, auto-deleting history, WhatsApp/Instagram sessions, Xiaomi ad settings, Sanchar Saathi (SIMs in your name, lost phones, IMEI check), a screen-sharing warning, and where to get help (1930 / cybercrime.gov.in).

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
- [malware-filter phishing-filter](https://gitlab.com/malware-filter/phishing-filter) (CC BY-SA 4.0; OpenPhish, PhishTank): `phishing_domains.txt`. [Phishing Army](https://phishing.army) and [HaGeZi Threat Intelligence Feeds, mini](https://github.com/hagezi/dns-blocklists) (GPL-3.0) are downloaded on update only.
- [Shizuku](https://github.com/RikkaApps/Shizuku) (Apache-2.0), optional.
- [abuse.ch](https://abuse.ch) MalwareBazaar & URLhaus.
- [Have I Been Pwned](https://haveibeenpwned.com) Pwned Passwords.

For personal use.
