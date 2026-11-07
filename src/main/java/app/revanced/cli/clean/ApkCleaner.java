package app.revanced.cli.clean;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.*;

/**
 * Zip/binary level APK cleaner used by the "patch" command (--clean* options) and usable standalone.
 * It does NOT decode or recompile resources (no apktool, no aapt2), so it is unaffected by Facebook's nameless
 * resource types ("invalid file path ... drawable.2-xxhdpi").
 * Never removes: AndroidManifest.xml, resources.arsc, classes*.dex, signature files, META-INF/services.
 */
public final class ApkCleaner {
    static final String[] PROTECTED = {
        ".*META-INF/MANIFEST\\.MF$", ".*META-INF/services/.*", ".*META-INF/.*\\.(RSA|SF|DSA|EC|FBSIG)$",
        "^(root/)?classes\\d*\\.dex$", ".*resources\\.arsc$", ".*AndroidManifest\\.xml$",
        // read at runtime by libraries (Compose version check, kotlin-reflect, javax.activation, ...): never delete
        "^META-INF/androidx\\.compose\\..*\\.version$", "^META-INF/.*\\.kotlin_module$", "^META-INF/mailcap.*", "^META-INF/mimetypes.*",
        "^META-INF/native/.*", "^META-INF/resources/.*",
    };

    // ---- From the original "APK Junk Cleanup" patch: for these apps the files in EXCLUDED_ROOT_CALLS made the app crash, so they are kept.
    // com.facebook.katana was added: Messenger (same code base) crashed without them, and these files are only ~3 KB in total.
    static final String[] EXCLUDED_PACKAGES = { "com.viber.voip", "com.facebook.orca", "com.whatsapp", "com.zing.zalo", "com.facebook.katana" };
    static final String[] EXCLUDED_ROOT_CALLS = {
        "play-services-auth.properties", "play-services-auth-api-phone.properties", "play-services-auth-base.properties",
        "play-services-base.properties", "play-services-cloud-messaging.properties", "play-services-gcm.properties",
        "play-services-tasks.properties", "firebase-auth.properties", "firebase-auth-interop.properties", "firebase-common.properties",
        "firebase-components.properties", "firebase-core.properties", "firebase-database.properties", "firebase-datatransport.properties",
        "firebase-inappmessaging.properties", "firebase-inappmessaging-display.properties", "firebase-messaging.properties",
        "core-common.properties", "META-INF/androidx.compose.ui_ui.version", "androidannotations-api.properties", "jetty-dir.css",
        "feature-delivery.properties", "feature-delivery-base.properties",
    };
// GENERATED from ApkJunkClean.kt (rv-NEW-patch22)
    static final String[] JUNK_REGEX = {
        ".*play-services-.*\\.properties$",
        ".*firebase-.*\\.properties$",
        ".*app-update\\.properties$",
        ".*billing\\.properties$",
        ".*billing-ktx\\.properties$",
        ".*review\\.properties$",
        ".*hsdp\\.properties$",
        ".*core-common\\.properties$",
        ".*user-messaging-platform\\.properties$",
        ".*feature-delivery.*\\.properties$",
        ".*ads-mobile-sdk\\.properties$",
        ".*\\.proto$",
        ".*DebugProbesKt\\.bin$",
        ".*\\.version$",
        ".*_VERSION$",
        ".*androidsupportmultidexversion\\.txt$",
        ".*stamp-cert-sha256$",
        ".*version-control-info\\.textproto$",
        ".*kotlin-tooling-metadata\\.json$",
        ".*META-INF/CHANGES$",
        ".*META-INF/README\\.md$",
        ".*META-INF/NOTICE.*",
        ".*META-INF/LICENSE.*",
        ".*(?:^|/)LICENSES$",
        ".*ion-java\\.properties$",
        ".*THIRD-PARTY-NOTICES\\.txt$",
        ".*licenses\\.md$",
        ".*debug\\.keystore$",
        ".*_trackers\\.xml$",
        ".*version\\.properties$",
        ".*integrity\\.properties$",
        ".*androidannotations-api\\.properties$",
        ".*transport-.*\\.properties$",
        ".*jetty-dir\\.css$",
    };
    static final String[] EXACT_JUNK = {
        "play-services-ads.properties",
        "play-services-ads-base.properties",
        "play-services-ads-identifier.properties",
        "play-services-ads-lite.properties",
        "play-services-analytics.properties",
        "play-services-analytics-impl.properties",
        "play-services-appset.properties",
        "play-services-auth.properties",
        "play-services-auth-api-phone.properties",
        "play-services-auth-base.properties",
        "play-services-base.properties",
        "play-services-basement.properties",
        "play-services-cast.properties",
        "play-services-cast-framework.properties",
        "play-services-clearcut.properties",
        "play-services-cloud-messaging.properties",
        "play-services-drive.properties",
        "play-services-fido.properties",
        "play-services-fitness.properties",
        "play-services-games.properties",
        "play-services-gcm.properties",
        "play-services-identity.properties",
        "play-services-location.properties",
        "play-services-maps.properties",
        "play-services-measurement.properties",
        "play-services-measurement-api.properties",
        "play-services-measurement-base.properties",
        "play-services-measurement-impl.properties",
        "play-services-measurement-sdk.properties",
        "play-services-measurement-sdk-api.properties",
        "play-services-oss-licenses.properties",
        "play-services-pay.properties",
        "play-services-places-placereport.properties",
        "play-services-safetynet.properties",
        "play-services-stats.properties",
        "play-services-tasks.properties",
        "play-services-vision.properties",
        "play-services-vision-common.properties",
        "play-services-wallet.properties",
        "play-services-wearable.properties",
        "firebase/perf/v1/perf_metric.proto",
        "firebase-ads.properties",
        "firebase-analytics.properties",
        "firebase-annotations.properties",
        "firebase-auth.properties",
        "firebase-auth-interop.properties",
        "firebase-common.properties",
        "firebase-components.properties",
        "firebase-config.properties",
        "firebase-core.properties",
        "firebase-crashlytics.properties",
        "firebase-database.properties",
        "firebase-datatransport.properties",
        "firebase-dynamic-links.properties",
        "firebase-encoders.properties",
        "firebase-encoders-proto.properties",
        "firebase-firestore.properties",
        "firebase-iid.properties",
        "firebase-iid-interop.properties",
        "firebase-inappmessaging.properties",
        "firebase-inappmessaging-display.properties",
        "firebase-installations.properties",
        "firebase-installations-interop.properties",
        "firebase-measurement-connector.properties",
        "firebase-messaging.properties",
        "firebase-perf.properties",
        "firebase-storage.properties",
        "transport-api.properties",
        "transport-backend-cct.properties",
        "transport-runtime.properties",
        "ion-java.properties",
        "feature-delivery.properties",
        "feature-delivery-base.properties",
        "facebook_trackers.xml",
        "google_trackers.xml",
        "firebase_trackers.xml",
        "client_analytics.proto",
        "messaging_event.proto",
        "messaging_event_extension.proto",
        "app-update.properties",
        "billing.properties",
        "billing-ktx.properties",
        "review.properties",
        "hsdp.properties",
        "core-common.properties",
        "user-messaging-platform.properties",
        "ads-mobile-sdk.properties",
        "DebugProbesKt.bin",
        "androidsupportmultidexversion.txt",
        "stamp-cert-sha256",
        "version-control-info.textproto",
        "kotlin-tooling-metadata.json",
        "LICENSES",
        "THIRD-PARTY-NOTICES.txt",
        "licenses.md",
        "debug.keystore",
        "version.properties",
        "integrity.properties",
        "androidannotations-api.properties",
        "jetty-dir.css",
        "tv-ads.properties",
    };
    static final String[] JUNK_DIRS = {
        "assets/dexopt/",
        "com/clevertap/",
        "org/jacoco/",
        "org/joda/",
        "services/",
    };


    // ---- Remove ad manifest entries (port tu DisableAdsEntries.kt) ----
    static final Set<String> AD_PERMS = new HashSet<>(Arrays.asList(
        "com.android.vending.CHECK_LICENSE", "com.google.android.gms.permission.AD_ID",
        "android.permission.ACCESS_ADSERVICES_ATTRIBUTION", "android.permission.ACCESS_ADSERVICES_AD_ID",
        "android.permission.ACCESS_ADSERVICES_TOPICS", "android.permission.ACCESS_ADSERVICES_CUSTOM_AUDIENCE",
        "android.permission.AD_SERVICES_CONFIG"));
    static final Set<String> GENERIC_PERMS = new HashSet<>(Arrays.asList(
        "android.permission.BLUETOOTH_ADVERTISE", "android.permission.CHANGE_NETWORK_STATE", "android.permission.CHANGE_WIFI_STATE",
        "android.permission.DETECT_SCREEN_CAPTURE", "android.permission.DETECT_SCREEN_RECORDING",
        "android.permission.KILL_BACKGROUND_PROCESSES", "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
        "android.permission.RUN_USER_INITIATED_JOBS"));
    static final String[] AD_NAMES = {
        "com.google.ads", "com.google.android.gms.ads", "com.google.android.tv.ads", "com.google.android.gms.measurement",
        "com.facebook.ads", "com.facebook.adspayments", "com.facebook.adscomposer", "com.facebook.adsconsentvalue",
        "com.facebook.bugreporter", "com.facebook.adinterfaces", "com.facebook.adspreviewinjection", "com.facebook.adpreview",
        "com.facebook.adsexperiencetool", "com.facebook.feed.platformads", "com.facebook.messaging.business.ads",
        "com.facebook.messaging.nativepagereply.adcreation", "com.facebook.messaging.professionalmode.adscreation",
        "com.facebook.partnershipads", "com.applovin", "com.mbridge.msdk", "com.inmobi.ads", "com.unity3d.ads",
        "com.unity3d.services.ads", "com.vungle", "com.ironsource", "com.bytedance.sdk", "com.anythink", "com.qq.e.",
        "com.baidu.mobads", "com.kwad.sdk", "com.sigmob", "com.tradplus", "com.pangle", "com.adtima.ads"};
    static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
    static final Pattern ADS_ASSET_1 = Pattern.compile("^assets/(?i:ads)[^/]*$");
    static final Pattern ADS_ASSET_2 = Pattern.compile("^assets/[^/]*(?i:ads)[^/]*Configs?\\.json$");

    static class Ent {
        byte[] name; String sname; int madeBy, needed, flags, method, time, date, nameLen, extraLen, commentLen, diskStart, intAttr;
        long crc, csize, usize, extAttr, locOff; byte[] cdExtra, comment; long newLocOff;
        byte[] mem; // noi dung moi (neu muc nay bi thay the)
    }

    // ---------------------------------------------------------------- byte helpers
    static int u8(byte[] b, int o) { return b[o] & 0xFF; }
    static int u16(byte[] b, int o) { return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8); }
    static int i32(byte[] b, int o) { return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8) | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24); }
    static long u32(byte[] b, int o) { return i32(b, o) & 0xFFFFFFFFL; }
    static void p32(byte[] b, int o, int v) { b[o] = (byte) v; b[o + 1] = (byte) (v >> 8); b[o + 2] = (byte) (v >> 16); b[o + 3] = (byte) (v >> 24); }
    static void w16(OutputStream o, int v) throws IOException { o.write(v & 0xFF); o.write((v >> 8) & 0xFF); }
    static void w32(OutputStream o, long v) throws IOException { w16(o, (int) (v & 0xFFFF)); w16(o, (int) ((v >> 16) & 0xFFFF)); }

    // ---------------------------------------------------------------- zip (central directory)
    static List<Ent> readCentralDirectory(RandomAccessFile f) throws IOException {
        long len = f.length(); int tail = (int) Math.min(len, 66000); byte[] t = new byte[tail];
        f.seek(len - tail); f.readFully(t);
        int e = -1; for (int i = tail - 22; i >= 0; i--) if (u32(t, i) == 0x06054b50L) { e = i; break; }
        if (e < 0) throw new IOException("EOCD not found - not a valid zip/APK file");
        long total = u16(t, e + 10), cdSize = u32(t, e + 12), cdOff = u32(t, e + 16);
        if (total == 0xFFFF || cdSize == 0xFFFFFFFFL || cdOff == 0xFFFFFFFFL) throw new IOException("ZIP64 is not supported");
        byte[] cd = new byte[(int) cdSize]; f.seek(cdOff); f.readFully(cd);
        List<Ent> list = new ArrayList<>(); int p = 0;
        while (p + 46 <= cd.length && u32(cd, p) == 0x02014b50L) {
            Ent x = new Ent();
            x.madeBy = u16(cd, p + 4); x.needed = u16(cd, p + 6); x.flags = u16(cd, p + 8); x.method = u16(cd, p + 10);
            x.time = u16(cd, p + 12); x.date = u16(cd, p + 14); x.crc = u32(cd, p + 16); x.csize = u32(cd, p + 20); x.usize = u32(cd, p + 24);
            x.nameLen = u16(cd, p + 28); x.extraLen = u16(cd, p + 30); x.commentLen = u16(cd, p + 32);
            x.diskStart = u16(cd, p + 34); x.intAttr = u16(cd, p + 36); x.extAttr = u32(cd, p + 38); x.locOff = u32(cd, p + 42);
            x.name = Arrays.copyOfRange(cd, p + 46, p + 46 + x.nameLen);
            x.cdExtra = Arrays.copyOfRange(cd, p + 46 + x.nameLen, p + 46 + x.nameLen + x.extraLen);
            x.comment = Arrays.copyOfRange(cd, p + 46 + x.nameLen + x.extraLen, p + 46 + x.nameLen + x.extraLen + x.commentLen);
            x.sname = new String(x.name, StandardCharsets.UTF_8);
            list.add(x); p += 46 + x.nameLen + x.extraLen + x.commentLen;
        }
        if (list.size() != total) throw new IOException("Central directory entry count mismatch: " + list.size() + " / " + total);
        return list;
    }

    static byte[] readEntry(RandomAccessFile f, Ent e) throws IOException {
        byte[] loc = new byte[30]; f.seek(e.locOff); f.readFully(loc);
        long ds = e.locOff + 30 + u16(loc, 26) + u16(loc, 28);
        byte[] raw = new byte[(int) e.csize]; f.seek(ds); f.readFully(raw);
        if (e.method == 0) return raw;
        Inflater inf = new Inflater(true); inf.setInput(raw);
        ByteArrayOutputStream bo = new ByteArrayOutputStream((int) Math.max(16, e.usize)); byte[] b = new byte[65536];
        try {
            while (!inf.finished()) {
                int n = inf.inflate(b);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                bo.write(b, 0, n);
            }
        } catch (DataFormatException ex) { throw new IOException("Inflate error: " + e.sname, ex); }
        inf.end(); return bo.toByteArray();
    }

    static byte[] deflateRaw(byte[] data) {
        Deflater d = new Deflater(Deflater.BEST_COMPRESSION, true); d.setInput(data); d.finish();
        ByteArrayOutputStream bo = new ByteArrayOutputStream(data.length / 2 + 64); byte[] b = new byte[65536];
        while (!d.finished()) { int n = d.deflate(b); bo.write(b, 0, n); }
        d.end(); return bo.toByteArray();
    }

    // ---------------------------------------------------------------- string pool (AXML + ARSC dung chung)
    static String[] readPool(byte[] b, int p) {
        int count = i32(b, p + 8), flags = i32(b, p + 16), strStart = i32(b, p + 20), hdr = u16(b, p + 2);
        boolean utf8 = (flags & 0x100) != 0; String[] out = new String[count];
        for (int i = 0; i < count; i++) {
            int o = p + strStart + i32(b, p + hdr + 4 * i);
            if (utf8) {
                int l1 = u8(b, o++); if ((l1 & 0x80) != 0) o++;
                int l = u8(b, o++); if ((l & 0x80) != 0) l = ((l & 0x7F) << 8) | u8(b, o++);
                out[i] = new String(b, o, l, StandardCharsets.UTF_8);
            } else {
                int l = u16(b, o); o += 2;
                if ((l & 0x8000) != 0) { l = ((l & 0x7FFF) << 16) | u16(b, o); o += 2; }
                out[i] = new String(b, o, l * 2, StandardCharsets.UTF_16LE);
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- AndroidManifest.xml nhi phan: go phan tu quang cao
    static byte[] stripManifest(byte[] m, boolean generic, List<String> removed) {
        if (m.length < 16 || u16(m, 0) != 0x0003) throw new IllegalArgumentException("Manifest is not binary XML (already decoded?)");
        String[] pool = null; int p = u16(m, 2);
        ByteArrayOutputStream out = new ByteArrayOutputStream(m.length); out.write(m, 0, p);
        while (p + 8 <= m.length) {
            int type = u16(m, p), size = i32(m, p + 4); if (size <= 0) break;
            if (type == 0x0001 && pool == null) pool = readPool(m, p);
            if (type == 0x0102 && pool != null) {
                String why = matchElement(m, p, pool, generic);
                if (why != null) {
                    removed.add(why); int depth = 1, q = p + size;
                    while (q + 8 <= m.length && depth > 0) {
                        int t = u16(m, q), s = i32(m, q + 4); if (s <= 0) break;
                        if (t == 0x0102) depth++; else if (t == 0x0103) depth--;
                        q += s;
                    }
                    p = q; continue;
                }
            }
            out.write(m, p, size); p += size;
        }
        byte[] r = out.toByteArray(); p32(r, 4, r.length); return r;
    }

    static String matchElement(byte[] m, int p, String[] pool, boolean generic) {
        int ni = i32(m, p + 20); if (ni < 0 || ni >= pool.length) return null;
        String tag = pool[ni];
        switch (tag) { case "uses-permission": case "uses-permission-sdk-23": case "uses-permission-sdk-m": case "uses-library": case "property": case "meta-data":
            case "provider": case "service": case "receiver": case "activity": case "activity-alias": break; default: return null; }
        int attrStart = u16(m, p + 24), attrSize = u16(m, p + 26), attrCount = u16(m, p + 28);
        String name = "", value = "", target = "";
        for (int i = 0; i < attrCount; i++) {
            int ao = p + 16 + attrStart + i * attrSize;
            int ns = i32(m, ao), an = i32(m, ao + 4);
            if (an < 0 || an >= pool.length || ns < 0 || ns >= pool.length || !ANDROID_NS.equals(pool[ns])) continue;
            int raw = i32(m, ao + 8), dt = u8(m, ao + 15), data = i32(m, ao + 16);
            String sv = (raw >= 0 && raw < pool.length) ? pool[raw] : ((dt == 3 && data >= 0 && data < pool.length) ? pool[data] : "");
            if (pool[an].equals("name")) name = sv; else if (pool[an].equals("value")) value = sv; else if (pool[an].equals("targetActivity")) target = sv;
        }
        boolean rm;
        switch (tag) {
            case "uses-permission": case "uses-permission-sdk-23": case "uses-permission-sdk-m":
                rm = AD_PERMS.contains(name) || (generic && GENERIC_PERMS.contains(name)); break;
            case "uses-library": rm = name.equals("android.ext.adservices"); break;
            case "property": rm = name.equals("android.adservices.AD_SERVICES_CONFIG"); break;
            // activity-alias: also drop an alias whose target activity is an ad activity, otherwise the manifest has an alias pointing to nothing (install fails)
            default: rm = false; for (String pf : AD_NAMES) if (name.startsWith(pf) || value.startsWith(pf) || target.startsWith(pf)) { rm = true; break; }
        }
        return rm ? tag + " " + (name.isEmpty() ? (value.isEmpty() ? target : value) : name) : null;
    }

    // ---------------------------------------------------------------- resources.arsc: go khoi ngon ngu khong can
    static class ArscResult { byte[] data; int removedChunks, totalTypeChunks; long removedBytes; Set<String> deletePaths = new TreeSet<>(); Map<String, Integer> byLang = new TreeMap<>(); boolean refsUnsafe; }

    static String langOf(byte[] a, int cfg) {
        if (u32(a, cfg) < 12) return null;
        int b0 = u8(a, cfg + 8), b1 = u8(a, cfg + 9); if (b0 == 0 && b1 == 0) return null;
        if ((b0 & 0x80) != 0) {
            char c1 = (char) ('a' + (b1 & 0x1f)), c2 = (char) ('a' + (((b1 & 0xe0) >> 5) + ((b0 & 0x03) << 3))), c3 = (char) ('a' + ((b0 & 0x7c) >> 2));
            return "" + c1 + c2 + c3;
        }
        return ("" + (char) b0 + (char) b1).toLowerCase(Locale.ROOT);
    }

    /** Gom cac chuoi (duong dan file) ma cac muc cua mot khoi type tro toi. */
    static void collectRefs(byte[] a, int q, String[] gpool, Set<String> into) {
        int hdr = u16(a, q + 2), size = i32(a, q + 4), flags = u8(a, q + 9), count = i32(a, q + 12), es = i32(a, q + 16);
        for (int i = 0; i < count; i++) {
            long off;
            if ((flags & 0x01) != 0) off = ((long) (u16(a, q + hdr + 4 * i + 2))) * 4;          // sparse
            else if ((flags & 0x02) != 0) { int v = u16(a, q + hdr + 2 * i); if (v == 0xFFFF) continue; off = v * 4L; }
            else { long v = u32(a, q + hdr + 4 * i); if (v == 0xFFFFFFFFL) continue; off = v; }
            int e = (int) (q + es + off); if (e + 8 > q + size) throw new IllegalStateException("entry outside chunk");
            int eflags = u16(a, e + 2);
            if ((eflags & 0x08) != 0) throw new IllegalStateException("compact entry");
            if ((eflags & 0x01) != 0) {
                int cnt = i32(a, e + 12);
                for (int k = 0; k < cnt; k++) { int vo = e + 16 + k * 12 + 4; if (u8(a, vo + 3) == 0x03) addRef(gpool, i32(a, vo + 4), into); }
            } else if (u8(a, e + 11) == 0x03) addRef(gpool, i32(a, e + 12), into);
        }
    }
    static void addRef(String[] gpool, int idx, Set<String> into) { if (idx >= 0 && idx < gpool.length && gpool[idx] != null && gpool[idx].indexOf('/') > 0) into.add(gpool[idx]); }

    static ArscResult pruneArsc(byte[] a, Set<String> keepLangs, Set<String> zipNames) {
        if (a.length < 12 || u16(a, 0) != 0x0002) throw new IllegalArgumentException("Invalid resources.arsc");
        ArscResult r = new ArscResult();
        int total = (int) Math.min(u32(a, 4), a.length), p = u16(a, 2);
        ByteArrayOutputStream out = new ByteArrayOutputStream(a.length); out.write(a, 0, p);
        String[] gpool = null; Set<String> kept = new HashSet<>(), gone = new HashSet<>();
        while (p + 8 <= total) {
            int type = u16(a, p), size = i32(a, p + 4); if (size <= 0) throw new IllegalStateException("chunk size <= 0");
            if (type == 0x0001 && gpool == null) { gpool = readPool(a, p); out.write(a, p, size); }
            else if (type == 0x0200) {
                int pHdr = u16(a, p + 2); ByteArrayOutputStream po = new ByteArrayOutputStream(size); po.write(a, p, pHdr);
                int q = p + pHdr, end = p + size;
                while (q + 8 <= end) {
                    int t = u16(a, q), s = i32(a, q + 4); if (s <= 0) throw new IllegalStateException("inner chunk size <= 0");
                    boolean drop = false;
                    if (t == 0x0201) {
                        r.totalTypeChunks++;
                        String lang = langOf(a, q + 20);
                        boolean remove = lang != null && !keepLangs.contains(lang);
                        try { collectRefs(a, q, gpool, remove ? gone : kept); } catch (RuntimeException ex) { if (remove) r.refsUnsafe = true; }
                        if (remove) { drop = true; r.removedChunks++; r.removedBytes += s; r.byLang.merge(lang, 1, Integer::sum); }
                    }
                    if (!drop) po.write(a, q, s);
                    q += s;
                }
                byte[] pb = po.toByteArray(); p32(pb, 4, pb.length); out.write(pb, 0, pb.length);
            } else out.write(a, p, size);
            p += size;
        }
        if (!r.refsUnsafe) for (String g : gone) if (!kept.contains(g) && zipNames.contains(g)) r.deletePaths.add(g);
        byte[] res = out.toByteArray(); p32(res, 4, res.length); r.data = res;
        return r;
    }

    // ---------------------------------------------------------------- minSdkVersion (--lower-sdk)
    /**
     * Lowers minSdkVersion in the binary AndroidManifest.xml. It only rewrites the value of the existing attribute (same size), so the string
     * pool and all chunk sizes stay as they are. It never raises the value.
     */
    static byte[] lowerMinSdk(byte[] m, int newMin, List<String> notes) {
        if (m.length < 16 || u16(m, 0) != 0x0003) throw new IllegalArgumentException("Manifest is not binary XML (already decoded?)");
        String[] pool = null; int p = u16(m, 2);
        while (p + 8 <= m.length) {
            int type = u16(m, p), size = i32(m, p + 4); if (size <= 0) break;
            if (type == 0x0001 && pool == null) pool = readPool(m, p);
            else if (type == 0x0102 && pool != null) {
                int ni = i32(m, p + 20);
                if (ni >= 0 && ni < pool.length && pool[ni].equals("uses-sdk")) {
                    int attrStart = u16(m, p + 24), attrSize = u16(m, p + 26), attrCount = u16(m, p + 28);
                    for (int i = 0; i < attrCount; i++) {
                        int ao = p + 16 + attrStart + i * attrSize;
                        int ns = i32(m, ao), an = i32(m, ao + 4);
                        if (an < 0 || an >= pool.length || ns < 0 || ns >= pool.length || !ANDROID_NS.equals(pool[ns]) || !pool[an].equals("minSdkVersion")) continue;
                        int dt = u8(m, ao + 15), data = i32(m, ao + 16);
                        if (dt == 0x10 || dt == 0x11) {
                            if (data <= newMin) { notes.add("minSdkVersion is already " + data + " (<= " + newMin + "): unchanged"); return m; }
                            notes.add("minSdkVersion " + data + " -> " + newMin);
                        } else if (dt == 0x03) {
                            notes.add("minSdkVersion (preview codename) -> " + newMin);
                        } else throw new IllegalStateException("minSdkVersion has an unexpected value type 0x" + Integer.toHexString(dt));
                        byte[] r = m.clone();
                        p32(r, ao + 8, -1);   // rawValue: none
                        r[ao + 15] = 0x10;    // TYPE_INT_DEC
                        p32(r, ao + 16, newMin);
                        return r;
                    }
                    notes.add("The manifest has no minSdkVersion (it defaults to 1): nothing to lower");
                    return m;
                }
            }
            p += size;
        }
        notes.add("The manifest has no <uses-sdk> element (minSdkVersion defaults to 1): nothing to lower");
        return m;
    }

    /** First bytes of an entry without reading all of it (n must be small). Null when it cannot be read. */
    static byte[] readHead(RandomAccessFile f, Ent e, int n) throws IOException {
        byte[] loc = new byte[30]; f.seek(e.locOff); f.readFully(loc);
        long ds = e.locOff + 30 + u16(loc, 26) + u16(loc, 28);
        int take = (int) Math.min(e.csize, e.method == 0 ? n : 4096);
        byte[] raw = new byte[take]; f.seek(ds); f.readFully(raw);
        if (e.method == 0) return raw.length > n ? Arrays.copyOf(raw, n) : raw;
        Inflater inf = new Inflater(true); inf.setInput(raw); byte[] o = new byte[n]; int got = 0;
        try {
            while (got < n && !inf.finished()) {
                int k = inf.inflate(o, got, n - got);
                if (k == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                got += k;
            }
        } catch (DataFormatException ex) { return null; } finally { inf.end(); }
        return Arrays.copyOf(o, got);
    }

    /** Lowering minSdk does not change the code: warn when a dex file is newer than what old Android versions read (038 = Android 8.0). */
    static void warnDex(RandomAccessFile f, List<Ent> all, int newMin, List<String> notes) throws IOException {
        int worst = 0; String where = null;
        for (Ent e : all) {
            String n = e.sname;
            if (n.indexOf('/') >= 0 || !n.startsWith("classes") || !n.endsWith(".dex")) continue;
            byte[] h = readHead(f, e, 8);
            if (h == null || h.length < 8 || h[0] != 'd' || h[1] != 'e' || h[2] != 'x' || h[3] != '\n') continue;
            int v = (h[4] - '0') * 100 + (h[5] - '0') * 10 + (h[6] - '0');
            if (v > worst) { worst = v; where = n; }
        }
        if (worst > 38) notes.add("WARNING: " + where + " is dex format 0" + worst + ". Android 8.x only reads up to 038, so with minSdk " + newMin
                + " the app may refuse to install or crash at start on Android older than 9. Lowering minSdk only edits the manifest, not the code.");
    }

    // ---------------------------------------------------------------- resources.arsc: bo ban sao anh cua cac mat do khong can (--clean-dpi)
    static final String[] DPI_NAMES = {"ldpi", "mdpi", "tvdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"};
    static final int[] DPI_VALUES = {120, 160, 213, 240, 320, 480, 640};
    static final int DENSITY_ANY = 0xFFFE, DENSITY_NONE = 0xFFFF;

    /** "xxhdpi", "420dpi" or "420" -> dpi values. */
    static int[] parseDensities(String s) {
        List<Integer> l = new ArrayList<>();
        for (String t : csv(s, true)) {
            int v = -1;
            for (int i = 0; i < DPI_NAMES.length; i++) if (DPI_NAMES[i].equals(t)) v = DPI_VALUES[i];
            if (v < 0) {
                try { v = Integer.parseInt(t.endsWith("dpi") ? t.substring(0, t.length() - 3) : t); } catch (NumberFormatException ex) { v = -1; }
            }
            if (v < 20 || v > 1280) throw new IllegalArgumentException("density list: unknown density '" + t + "' (use ldpi, mdpi, tvdpi, hdpi, xhdpi, xxhdpi, xxxhdpi or a number such as 420)");
            if (!l.contains(v)) l.add(v);
        }
        if (l.isEmpty()) throw new IllegalArgumentException("density list: no density given");
        int[] r = new int[l.size()]; for (int i = 0; i < r.length; i++) r[i] = l.get(i); return r;
    }

    static String dpiLabel(int d) {
        if (d == 0) return "default";
        if (d == DENSITY_ANY) return "anydpi"; if (d == DENSITY_NONE) return "nodpi";
        for (int i = 0; i < DPI_VALUES.length; i++) if (DPI_VALUES[i] == d) return DPI_NAMES[i];
        return d + "dpi";
    }

    /** The density Android picks for a screen of density t among the available ones: exact, else the smallest above, else the largest below. */
    static int bestDensity(int t, int[] av) {
        int above = Integer.MAX_VALUE, below = -1;
        for (int d : av) { if (d == t) return d; if (d > t) above = Math.min(above, d); else below = Math.max(below, d); }
        return above != Integer.MAX_VALUE ? above : below;
    }

    static boolean isImagePath(String s) {
        int d = s.lastIndexOf('.'); if (d < 0) return false;
        String x = s.substring(d + 1).toLowerCase(Locale.ROOT);
        return x.equals("png") || x.equals("webp") || x.equals("jpg") || x.equals("jpeg") || x.equals("gif");
    }

    static class DpiResult { byte[] data; int removedEntries, changedChunks, droppedChunks, skippedGroups; boolean refsUnsafe; Set<String> deletePaths = new TreeSet<>(); Map<String, Integer> byDensity = new TreeMap<>(); }

    /** One ResTable_type chunk: the entries of one resource type for one configuration. Slot = position in the offset table (sparse: in the pair table). */
    static final class TChunk {
        int pos, size, hdr, pkg, typeId, flags, count, entriesStart, density, eff, slots;
        String key;      // package + type id + the whole configuration except its density
        int[] slotIdx;   // entry index of each slot
        int[] eoff;      // offset of the entry (relative to entriesStart) or -1 = empty slot
        int[] esize;     // byte size of the entry
        String[] image;  // path when the entry is a plain reference to an image file in the APK, else null
        boolean[] drop;
        boolean ok;      // every entry was understood, so the chunk can be rebuilt
        boolean any() { for (boolean b : drop) if (b) return true; return false; }
    }

    static String hex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x & 0xFF)); return sb.toString(); }

    /** All string-pool references (file paths) of one entry. */
    static void entryRefs(byte[] a, int e, String[] gpool, Set<String> into) {
        int esz = u16(a, e), ef = u16(a, e + 2);
        if ((ef & 0x01) != 0) {
            int cnt = i32(a, e + 12);
            for (int k = 0; k < cnt; k++) { int vo = e + esz + k * 12 + 4; if (u8(a, vo + 3) == 0x03) addRef(gpool, i32(a, vo + 4), into); }
        } else if (u8(a, e + esz + 3) == 0x03) addRef(gpool, i32(a, e + esz + 4), into);
    }

    /** Reads a type chunk. Paths of entries that can never be removed are added to {@code kept}; image entries are decided later. */
    static TChunk parseType(byte[] a, int q, int pkgNo, String[] gpool, Set<String> zipNames, Set<String> kept) {
        TChunk c = new TChunk(); c.pos = q; c.pkg = pkgNo; c.hdr = u16(a, q + 2); c.size = i32(a, q + 4);
        c.typeId = u8(a, q + 8); c.flags = u8(a, q + 9); c.count = i32(a, q + 12); c.entriesStart = i32(a, q + 16);
        c.slots = 0; c.drop = new boolean[0];
        try {
            int cfg = q + 20, cfgSize = i32(a, cfg);
            if ((c.flags & ~3) != 0 || c.count < 0 || c.count > 0xFFFF + 1 || cfgSize < 16 || cfgSize > 256 || 20 + cfgSize > c.hdr || c.entriesStart < c.hdr || c.entriesStart > c.size) return c;
            c.density = u16(a, cfg + 14); c.eff = c.density == 0 ? 160 : c.density;
            byte[] kb = Arrays.copyOfRange(a, cfg, cfg + cfgSize); kb[14] = 0; kb[15] = 0;
            if (cfgSize >= 26 && u16(kb, 24) <= 4) { kb[24] = 0; kb[25] = 0; } // "-v4" (old aapt) means the same as no version
            c.key = pkgNo + ":" + c.typeId + ":" + hex(kb);
            boolean sparse = (c.flags & 1) != 0, off16 = (c.flags & 2) != 0;
            int n = c.count, end = q + c.size;
            if (q + c.hdr + (sparse ? 4 : off16 ? 2 : 4) * n > end) return c;
            c.slots = n; c.slotIdx = new int[n]; c.eoff = new int[n]; c.esize = new int[n]; c.image = new String[n]; c.drop = new boolean[n];
            for (int i = 0; i < n; i++) {
                long off;
                if (sparse) { c.slotIdx[i] = u16(a, q + c.hdr + 4 * i); off = (long) u16(a, q + c.hdr + 4 * i + 2) * 4; }
                else if (off16) { c.slotIdx[i] = i; int v = u16(a, q + c.hdr + 2 * i); off = v == 0xFFFF ? -1 : v * 4L; }
                else { c.slotIdx[i] = i; long v = u32(a, q + c.hdr + 4 * i); off = v == 0xFFFFFFFFL ? -1 : v; }
                if (off < 0) { c.eoff[i] = -1; continue; }
                int e = (int) (q + c.entriesStart + off);
                if (off > c.size || e + 8 > end) { c.slots = 0; return c; }
                int esz = u16(a, e), ef = u16(a, e + 2), total;
                if ((ef & 0x08) != 0) { c.slots = 0; return c; }               // compact entry: not supported
                if ((ef & 0x01) != 0) {
                    if (esz < 16 || e + 16 > end) { c.slots = 0; return c; }
                    int cnt = i32(a, e + 12); if (cnt < 0 || cnt > 100000) { c.slots = 0; return c; }
                    total = esz + cnt * 12;
                } else {
                    if (esz < 8 || e + esz + 8 > end || u16(a, e + esz) != 8) { c.slots = 0; return c; }
                    total = esz + 8;
                }
                if (e + total > end) { c.slots = 0; return c; }
                c.eoff[i] = (int) off; c.esize[i] = total;
                if ((ef & 0x01) == 0 && u8(a, e + esz + 3) == 0x03) {
                    int di = i32(a, e + esz + 4);
                    String path = di >= 0 && di < gpool.length ? gpool[di] : null;
                    if (path != null && path.indexOf('/') > 0 && isImagePath(path) && zipNames.contains(path)) { c.image[i] = path; continue; }
                }
                entryRefs(a, e, gpool, kept);
            }
            // entries must not overlap or share an offset, otherwise rebuilding the chunk would be wrong
            Integer[] order = new Integer[n]; for (int i = 0; i < n; i++) order[i] = i;
            final TChunk cc = c; Arrays.sort(order, (x, y) -> Integer.compare(cc.eoff[x], cc.eoff[y]));
            int lastEnd = -1;
            for (int i : order) {
                if (c.eoff[i] < 0) continue;
                if (c.eoff[i] < lastEnd) { c.slots = 0; return c; }
                lastEnd = c.eoff[i] + c.esize[i];
            }
            c.ok = true;
        } catch (RuntimeException ex) { c.slots = 0; c.ok = false; }
        return c;
    }

    /** Builds the type chunk again without the dropped entries. Returns null when nothing is left. */
    static byte[] rebuildType(byte[] a, TChunk c) {
        boolean sparse = (c.flags & 1) != 0, off16 = (c.flags & 2) != 0;
        List<Integer> keep = new ArrayList<>();
        for (int i = 0; i < c.slots; i++) if (c.eoff[i] >= 0 && !c.drop[i]) keep.add(i);
        if (keep.isEmpty()) return null;
        int n = sparse ? keep.size() : c.count;
        int arr = ((sparse ? 4 * n : off16 ? 2 * n : 4 * n) + 3) & ~3;
        int newEs = c.hdr + arr;
        ByteArrayOutputStream data = new ByteArrayOutputStream(); int[] newOff = new int[c.slots]; Arrays.fill(newOff, -1);
        for (int i : keep) {
            newOff[i] = data.size(); data.write(a, c.pos + c.entriesStart + c.eoff[i], c.esize[i]);
            while (data.size() % 4 != 0) data.write(0);
        }
        byte[] r = new byte[newEs + data.size()];
        System.arraycopy(a, c.pos, r, 0, c.hdr);
        p32(r, 4, r.length); p32(r, 16, newEs);
        if (sparse) {
            p32(r, 12, n);
            for (int j = 0; j < keep.size(); j++) {
                int slot = keep.get(j), o = c.hdr + 4 * j;
                r[o] = (byte) c.slotIdx[slot]; r[o + 1] = (byte) (c.slotIdx[slot] >> 8);
                int v = newOff[slot] / 4; r[o + 2] = (byte) v; r[o + 3] = (byte) (v >> 8);
            }
        } else if (off16) {
            for (int i = 0; i < n; i++) {
                int v = newOff[i] < 0 ? 0xFFFF : newOff[i] / 4;
                if (v >= 0xFFFF && newOff[i] >= 0) throw new IllegalStateException("offset16 overflow");
                r[c.hdr + 2 * i] = (byte) v; r[c.hdr + 2 * i + 1] = (byte) (v >> 8);
            }
            for (int o = c.hdr + 2 * n; o < newEs; o++) r[o] = 0;
        } else {
            for (int i = 0; i < n; i++) p32(r, c.hdr + 4 * i, newOff[i] < 0 ? 0xFFFFFFFF : newOff[i]);
        }
        byte[] d = data.toByteArray(); System.arraycopy(d, 0, r, newEs, d.length);
        return r;
    }

    /**
     * Keeps, for every image that exists in several screen densities, only the copy Android would pick for the given densities.
     * Only plain file references to png/webp/jpg/gif are touched, and only when ALL copies of that entry are such files in the same
     * configuration apart from density. Resource ids, entry counts and everything else stay as they are.
     */
    static DpiResult pruneDensity(byte[] a, int[] targets, Set<String> zipNames) {
        if (a.length < 12 || u16(a, 0) != 0x0002) throw new IllegalArgumentException("Invalid resources.arsc");
        DpiResult r = new DpiResult();
        int total = (int) Math.min(u32(a, 4), a.length), p0 = u16(a, 2);
        String[] gpool = null; Set<String> kept = new HashSet<>(), gone = new HashSet<>();
        List<TChunk> chunks = new ArrayList<>(); Map<Integer, TChunk> byPos = new HashMap<>();
        int pp = p0, pkgNo = 0;
        while (pp + 8 <= total) {                       // pass 1: read every type chunk
            int type = u16(a, pp), size = i32(a, pp + 4); if (size <= 0) throw new IllegalStateException("chunk size <= 0");
            if (type == 0x0001 && gpool == null) gpool = readPool(a, pp);
            else if (type == 0x0200) {
                if (gpool == null) throw new IllegalStateException("package before the string pool");
                int q = pp + u16(a, pp + 2), end = pp + size;
                while (q + 8 <= end) {
                    int t = u16(a, q), s = i32(a, q + 4); if (s <= 0) throw new IllegalStateException("inner chunk size <= 0");
                    if (t == 0x0201) {
                        TChunk c = parseType(a, q, pkgNo, gpool, zipNames, kept);
                        if (!c.ok) { try { collectRefs(a, q, gpool, kept); } catch (RuntimeException ex) { r.refsUnsafe = true; } }
                        chunks.add(c); byPos.put(q, c);
                    }
                    q += s;
                }
                pkgNo++;
            }
            pp += size;
        }
        Map<String, List<TChunk>> groups = new LinkedHashMap<>();
        for (TChunk c : chunks) if (c.ok) groups.computeIfAbsent(c.key, k -> new ArrayList<>()).add(c);
        for (List<TChunk> g : groups.values()) {        // pass 2: decide per entry
            if (g.size() < 2) continue;
            Map<Integer, List<int[]>> byEntry = new TreeMap<>();
            for (int gi = 0; gi < g.size(); gi++) {
                TChunk c = g.get(gi);
                for (int sl = 0; sl < c.slots; sl++) if (c.eoff[sl] >= 0) byEntry.computeIfAbsent(c.slotIdx[sl], k -> new ArrayList<>()).add(new int[]{gi, sl});
            }
            for (List<int[]> cand : byEntry.values()) {
                if (cand.size() < 2) continue;
                boolean eligible = true; Set<Integer> effs = new LinkedHashSet<>();
                for (int[] cs : cand) {
                    TChunk c = g.get(cs[0]);
                    if (c.image[cs[1]] == null || c.density == DENSITY_ANY || c.density == DENSITY_NONE || !effs.add(c.eff)) { eligible = false; break; }
                }
                if (!eligible) continue;
                int[] av = new int[effs.size()]; int k = 0; for (int d : effs) av[k++] = d;
                Set<Integer> keepD = new HashSet<>(); for (int t : targets) keepD.add(bestDensity(t, av));
                for (int[] cs : cand) {
                    TChunk c = g.get(cs[0]);
                    if (!keepD.contains(c.eff)) { c.drop[cs[1]] = true; r.removedEntries++; r.byDensity.merge(dpiLabel(c.density), 1, Integer::sum); }
                }
            }
        }
        for (TChunk c : chunks) for (int sl = 0; sl < c.slots; sl++) {
            if (c.image[sl] != null) (c.drop[sl] ? gone : kept).add(c.image[sl]);
        }
        if (!r.refsUnsafe) for (String g : gone) if (!kept.contains(g) && zipNames.contains(g)) r.deletePaths.add(g);
        ByteArrayOutputStream out = new ByteArrayOutputStream(a.length); out.write(a, 0, p0);
        pp = p0;                                        // pass 3: write the table again
        while (pp + 8 <= total) {
            int type = u16(a, pp), size = i32(a, pp + 4);
            if (type == 0x0200) {
                int pHdr = u16(a, pp + 2); ByteArrayOutputStream po = new ByteArrayOutputStream(size); po.write(a, pp, pHdr);
                int q = pp + pHdr, end = pp + size;
                while (q + 8 <= end) {
                    int t = u16(a, q), s = i32(a, q + 4);
                    TChunk c = t == 0x0201 ? byPos.get(q) : null;
                    if (c != null && c.ok && c.any()) {
                        byte[] nb = rebuildType(a, c);
                        if (nb == null) r.droppedChunks++; else { r.changedChunks++; po.write(nb, 0, nb.length); }
                    } else po.write(a, q, s);
                    q += s;
                }
                byte[] pb = po.toByteArray(); p32(pb, 4, pb.length); out.write(pb, 0, pb.length);
            } else out.write(a, pp, size);
            pp += size;
        }
        byte[] res = out.toByteArray(); p32(res, 4, res.length); r.data = res;
        return r;
    }

    // ---------------------------------------------------------------- PNG khong mat du lieu
    static final byte[] PNG_SIG = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    static final Set<String> STRIP = new HashSet<>(Arrays.asList("tEXt", "zTXt", "iTXt", "tIME", "pHYs", "hIST", "sPLT"));
    static int be32(byte[] b, int o) { return ((b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF); }

    static byte[] optimizePng(byte[] d) {
        if (d.length < 20 || !Arrays.equals(Arrays.copyOf(d, 8), PNG_SIG)) return null;
        List<String> types = new ArrayList<>(); List<byte[]> datas = new ArrayList<>();
        int o = 8; ByteArrayOutputStream idat = new ByteArrayOutputStream();
        while (o + 12 <= d.length) {
            int len = be32(d, o); if (len < 0 || o + 12 + len > d.length) return null;
            String t = new String(d, o + 4, 4, StandardCharsets.US_ASCII);
            CRC32 c = new CRC32(); c.update(d, o + 4, 4 + len); if ((int) c.getValue() != be32(d, o + 8 + len)) return null;
            byte[] data = Arrays.copyOfRange(d, o + 8, o + 8 + len);
            if (t.equals("IDAT")) idat.write(data, 0, data.length);
            types.add(t); datas.add(data); o += 12 + len;
        }
        byte[] raw;
        try {
            Inflater inf = new Inflater(); inf.setInput(idat.toByteArray()); ByteArrayOutputStream ro = new ByteArrayOutputStream(); byte[] b = new byte[65536];
            while (!inf.finished()) { int n = inf.inflate(b); if (n == 0 && (inf.needsInput() || inf.needsDictionary())) return null; ro.write(b, 0, n); }
            inf.end(); raw = ro.toByteArray();
        } catch (DataFormatException ex) { return null; }
        Deflater df = new Deflater(Deflater.BEST_COMPRESSION); df.setInput(raw); df.finish();
        ByteArrayOutputStream co = new ByteArrayOutputStream(); byte[] b = new byte[65536];
        while (!df.finished()) { int n = df.deflate(b); co.write(b, 0, n); } df.end();
        byte[] comp = co.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream(d.length); out.write(PNG_SIG, 0, 8); boolean idatDone = false;
        for (int i = 0; i < types.size(); i++) {
            String t = types.get(i);
            if (STRIP.contains(t)) continue;
            if (t.equals("IDAT")) { if (idatDone) continue; idatDone = true; putChunk(out, "IDAT", comp); continue; }
            putChunk(out, t, datas.get(i));
        }
        byte[] res = out.toByteArray();
        return res.length < d.length ? res : null;
    }
    static void putChunk(ByteArrayOutputStream out, String t, byte[] data) {
        byte[] hd = new byte[8]; hd[0] = (byte) (data.length >>> 24); hd[1] = (byte) (data.length >>> 16); hd[2] = (byte) (data.length >>> 8); hd[3] = (byte) data.length;
        byte[] tb = t.getBytes(StandardCharsets.US_ASCII); System.arraycopy(tb, 0, hd, 4, 4); out.write(hd, 0, 8); out.write(data, 0, data.length);
        CRC32 c = new CRC32(); c.update(tb); c.update(data); int v = (int) c.getValue();
        out.write(v >>> 24); out.write(v >>> 16); out.write(v >>> 8); out.write(v);
    }

    // ---------------------------------------------------------------- chinh
    static List<Pattern> compile(String[] a) { List<Pattern> l = new ArrayList<>(); for (String s : a) l.add(Pattern.compile(s)); return l; }

    /** Options of one cleaning run. All fields are plain values so Kotlin/CLI code can set them directly. */
    public static final class Options {
        /**
         * Safe junk rules: licenses/notices, .proto, tracker lists, library version marker files (*.properties, *.version of
         * ad/analytics/Play Services libraries...), org/jacoco/, META-INF/maven and META-INF/proguard. The files known to crash some apps
         * (EXCLUDED_ROOT_CALLS) are kept unless aggressive is set.
         */
        public boolean junk = true;
        /** Comma separated ABI names to keep inside lib/ (e.g. "armeabi-v7a"); null or empty = keep all. */
        public String keepAbi;
        /** Also delete assets/dexopt/ (baseline profile). */
        public boolean dropBaseline;
        /** Delete assets/Ads* and assets/*Ads*Configs.json. */
        public boolean adsAssets;
        /** Remove ad components from the binary AndroidManifest.xml. */
        public boolean manifestAds;
        /** With manifestAds: also remove generic permissions (CHANGE_NETWORK_STATE, ...). Risky. */
        public boolean genericPerms;
        /** Comma separated languages to keep (e.g. "en,vi"); null or empty = keep all languages. */
        public String langs;
        /** Lossless PNG re-compression. */
        public boolean png;
        /** Lower minSdkVersion in AndroidManifest.xml to this API level (0 = leave as is). Never raises it. */
        public int minSdk;
        /**
         * Densities to keep for images that exist in several densities (e.g. "xxhdpi" or "xhdpi,xxhdpi" or "420"); null or empty = keep all.
         * For every image the copy Android would choose for each listed density is kept, the other densities of the same image are removed.
         */
        public String dpi;
        /**
         * Also apply the riskier rules (implies junk): the library files known to crash some apps (EXCLUDED_ROOT_CALLS: play-services-auth/base/tasks,
         * firebase-common/messaging/..., core-common, ...) and the folders kotlin/, org/joda/, com/clevertap/, services/, assets/audience_network*,
         * and every other META-INF entry. Some apps read these at runtime and crash or misbehave without them.
         */
        public boolean aggressive;
        /** Comma separated extra paths/globs that must never be deleted (* = any characters, ? = one character), e.g. "play-services-base.properties,*.kotlin_module". */
        public String protect;
        /** true = only list what would be removed and write nothing (out may be null). */
        public boolean dryRun;

        /** true when this run has anything to do (any option beyond defaults is set). */
        public boolean hasWork() {
            return junk || aggressive || notEmpty(keepAbi) || dropBaseline || adsAssets || manifestAds || notEmpty(langs) || png || minSdk > 0 || notEmpty(dpi);
        }
    }

    /** Summary of one cleaning run. */
    public static final class Result {
        public int removedFiles, keptEntries;
        public long removedBytes, removedCompressedBytes, inputSize, outputSize;
    }

    static boolean notEmpty(String s) { return s != null && !s.trim().isEmpty(); }

    /**
     * Language list -> language codes as Android stores them. "en-rUS", "en-US", "en_US" and "b+en+US" all mean "en" (every region of a language is kept),
     * and "id", "he", "yi" become the old codes "in", "iw", "ji" that Android uses in resource tables.
     */
    static Set<String> normLangs(String s) {
        Set<String> r = new LinkedHashSet<>();
        for (String t : csv(s, true)) {
            String l = t.startsWith("b+") ? t.substring(2).split("\\+")[0] : t.split("[-_]")[0];
            if (l.length() < 2 || l.length() > 3 || !l.chars().allMatch(ch -> ch >= 'a' && ch <= 'z'))
                throw new IllegalArgumentException("'" + t + "' is not a language code (use codes such as en,vi,pt-BR)");
            r.add(l.equals("id") ? "in" : l.equals("he") ? "iw" : l.equals("yi") ? "ji" : l);
        }
        return r;
    }

    static Set<String> csv(String s, boolean lower) {
        Set<String> set = new LinkedHashSet<>();
        if (s != null) for (String p : s.split(",")) { p = p.trim(); if (!p.isEmpty()) set.add(lower ? p.toLowerCase(Locale.ROOT) : p); }
        return set;
    }

    /** Command-line entry (standalone): java -cp revanced-cli-all.jar app.revanced.cli.clean.ApkCleaner in.apk [out.apk] [options] */
    public static void main(String[] args) throws Exception {
        Options o = new Options(); o.junk = true; List<String> pos = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--keep-abi": o.keepAbi = args[++i]; break;
                case "--drop-baseline": o.dropBaseline = true; break;
                case "--no-junk": o.junk = false; break;
                case "--aggressive": o.aggressive = true; break;
                case "--protect": o.protect = args[++i]; break;
                case "--ads-assets": o.adsAssets = true; break;
                case "--manifest-ads": o.manifestAds = true; break;
                case "--manifest-generic-perms": o.genericPerms = true; break;
                case "--png": o.png = true; break;
                case "--langs": o.langs = args[++i]; break;
                case "--dpi": o.dpi = args[++i]; break;
                case "--lower-sdk": o.minSdk = Integer.parseInt(args[++i]); break;
                default: pos.add(args[i]);
            }
        }
        if (pos.size() < 1 || pos.size() > 2) { System.err.println("Usage: ApkCleaner in.apk [out.apk] [options]   (without out.apk = dry run)"); System.exit(2); }
        File in = new File(pos.get(0)); File out = pos.size() == 2 ? new File(pos.get(1)) : null;
        o.dryRun = out == null;
        clean(in, out, o, System.out::println);
    }

    /**
     * Cleans {@code in} into {@code out} at zip level (no decode, no aapt2). Unchanged entries are copied byte for byte
     * (still compressed); STORED entries are aligned like zipalign. The output is NOT signed.
     */
    public static Result clean(File in, File out, Options opt, java.util.function.Consumer<String> log) throws IOException {
        if (!opt.dryRun) {
            if (out == null) throw new IllegalArgumentException("out is required unless dryRun");
            if (in.getCanonicalFile().equals(out.getCanonicalFile())) throw new IllegalArgumentException("out must differ from in");
        }
        Set<String> keepAbi = csv(opt.keepAbi, false); if (keepAbi.isEmpty()) keepAbi = null;
        Set<String> langs = normLangs(opt.langs); if (langs.isEmpty()) langs = null;
        boolean junkOn = opt.junk || opt.aggressive;
        Ctx cx = new Ctx(); cx.keepAbi = keepAbi; cx.dropBaseline = opt.dropBaseline; cx.junkOn = junkOn; cx.aggressive = opt.aggressive;
        cx.prot = compile(PROTECTED);
        for (String g : csv(opt.protect, false)) cx.userProtect.add(Pattern.compile(globToRegex(g)));
        for (String re : JUNK_REGEX) cx.junk.add(Pattern.compile(re));
        cx.exact.addAll(Arrays.asList(EXACT_JUNK));
        boolean dryRun = opt.dryRun;

        Result res = new Result(); res.inputSize = in.length();
        Map<String, long[]> byWhy = new TreeMap<>();
        List<String> notes = new ArrayList<>();
        List<Ent> keep = new ArrayList<>();
        try (RandomAccessFile f = new RandomAccessFile(in, "r")) {
            List<Ent> all = readCentralDirectory(f);
            Set<String> names = new HashSet<>(); for (Ent e : all) names.add(e.sname);
            Map<String, String> extraDelete = new HashMap<>(); // path -> reason
            Map<String, byte[]> repl = new HashMap<>();
            Map<String, Ent> byName = new HashMap<>(); for (Ent e : all) byName.put(e.sname, e);

            if (junkOn) {
                Ent me0 = byName.get("AndroidManifest.xml");
                String pkg = null;
                if (me0 != null) { try { pkg = readPackage(readEntry(f, me0)); } catch (RuntimeException ex) { notes.add("WARNING: could not read the package name: " + ex.getMessage()); } }
                cx.excludedApp = pkg != null && Arrays.asList(EXCLUDED_PACKAGES).contains(pkg);
                Ent ae0 = byName.get("resources.arsc");
                if (ae0 != null) {
                    try { cx.refs = arscRefs(readEntry(f, ae0), names); }
                    catch (RuntimeException ex) { cx.shieldDeep = true; notes.add("WARNING: could not read resources.arsc (" + ex.getMessage() + "): all files in sub-folders are protected from junk rules"); }
                }
                notes.add("Junk rules: package " + pkg + (cx.excludedApp ? " is on the exclusion list: " + EXCLUDED_ROOT_CALLS.length + " known-sensitive library files are kept" : "")
                        + "; " + cx.refs.size() + " files used by the resource table are protected" + (opt.aggressive ? "; AGGRESSIVE mode" : "; safe mode (add --clean-aggressive for the known-sensitive library files, kotlin/, org/joda/, other META-INF)"));
            }
            if (opt.minSdk > 0 || opt.manifestAds) {
                Ent me = byName.get("AndroidManifest.xml");
                if (me == null) throw new IOException("AndroidManifest.xml not found in the APK");
                byte[] man = readEntry(f, me);
                if (opt.minSdk > 0) {
                    if (opt.minSdk > 99) throw new IllegalArgumentException("--lower-sdk: " + opt.minSdk + " is not a valid API level (use 1..99)");
                    man = lowerMinSdk(man, opt.minSdk, notes);
                    if (opt.minSdk < 28) warnDex(f, all, opt.minSdk, notes);
                }
                if (opt.manifestAds) {
                    List<String> rm = new ArrayList<>();
                    man = stripManifest(man, opt.genericPerms, rm);
                    notes.add("Manifest: removed " + rm.size() + " ad entries" + (opt.genericPerms ? " (including generic permissions)" : ""));
                    for (String s : rm) notes.add("    - " + s);
                }
                repl.put("AndroidManifest.xml", man);
            }
            if (langs != null) {
                Ent ae = byName.get("resources.arsc");
                if (ae == null) throw new IOException("resources.arsc not found in the APK");
                ArscResult ar = pruneArsc(readEntry(f, ae), langs, names);
                repl.put("resources.arsc", ar.data);
                notes.add("Languages: keeping " + langs + "; removed " + ar.removedChunks + "/" + ar.totalTypeChunks + " type chunks ("
                        + ar.removedBytes + " B) of languages " + ar.byLang + "; " + ar.deletePaths.size() + " files used only by them deleted"
                        + (ar.refsUnsafe ? " [WARNING: could not determine which files they use -> no files deleted]" : ""));
                for (String s : ar.deletePaths) extraDelete.put(s, "file of removed language");
            }
            if (notEmpty(opt.dpi)) {
                int[] targets = parseDensities(opt.dpi);
                Ent ae = byName.get("resources.arsc");
                if (ae == null) throw new IOException("resources.arsc not found in the APK");
                byte[] cur = repl.containsKey("resources.arsc") ? repl.get("resources.arsc") : readEntry(f, ae);
                DpiResult dr = pruneDensity(cur, targets, names);
                repl.put("resources.arsc", dr.data);
                notes.add("Densities: keeping the copy Android picks for " + opt.dpi + "; " + dr.removedEntries + " image entries removed from "
                        + dr.changedChunks + " type chunks (" + dr.droppedChunks + " chunks became empty and were dropped), by density " + dr.byDensity + "; "
                        + dr.deletePaths.size() + " image files no longer used are deleted"
                        + (dr.refsUnsafe ? " [WARNING: could not read some resource entries -> no files deleted]" : "")
                        + (dr.skippedGroups > 0 ? " [" + dr.skippedGroups + " groups left untouched: unsupported entry format]" : ""));
                for (String s : dr.deletePaths) extraDelete.put(s, "image of removed density");
            }
            if (opt.png) {
                long saved = 0; int n = 0;
                for (Ent e : all) if (e.sname.toLowerCase(Locale.ROOT).endsWith(".png") && !e.sname.endsWith("/")) {
                    byte[] o = optimizePng(readEntry(f, e));
                    if (o != null) { repl.put(e.sname, o); saved += e.usize - o.length; n++; }
                }
                notes.add("PNG: " + n + " files smaller, " + saved + " B saved (before compression)");
            }

            for (Ent e : all) {
                boolean dir = e.sname.endsWith("/");
                String why = null;
                if (!dir) {
                    if (cx.isUserProtected(e.sname)) why = null;
                    else if (extraDelete.containsKey(e.sname)) why = extraDelete.get(e.sname);
                    else if (opt.adsAssets && (ADS_ASSET_1.matcher(e.sname).matches() || ADS_ASSET_2.matcher(e.sname).matches())) why = "ads assets (Ads*)";
                    else why = reason(e.sname, cx);
                }
                if (why != null) {
                    res.removedFiles++; res.removedBytes += e.usize; res.removedCompressedBytes += e.csize;
                    long[] a = byWhy.computeIfAbsent(why, k -> new long[2]); a[0]++; a[1] += e.usize;
                    if (dryRun) log.accept("  - " + e.sname + "  (" + e.usize + " B)  [" + why + "]");
                } else if (!dir) { if (repl.containsKey(e.sname)) e.mem = repl.get(e.sname); keep.add(e); }
            }
            res.keptEntries = keep.size();
            if (!dryRun) {
                File parent = out.getAbsoluteFile().getParentFile();
                if (parent != null) parent.mkdirs();
                // Ghi ra file .part roi doi ten: neu loi giua chung thi khong de lai file APK cat dut.
                File part = new File(out.getPath() + ".part");
                try {
                    write(f, keep, part);
                    java.nio.file.Files.move(part.toPath(), out.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } finally {
                    part.delete(); // khong con gi de xoa sau khi doi ten thanh cong
                }
                res.outputSize = out.length();
            }
        }
        for (String s : notes) log.accept(s);
        for (Map.Entry<String, long[]> e : byWhy.entrySet())
            log.accept(String.format(Locale.ROOT, "  %-28s %5d files  %10d B", e.getKey(), e.getValue()[0], e.getValue()[1]));
        log.accept(String.format(Locale.ROOT, "Total: %d files removed (%d B, %d B compressed); %d entries kept.", res.removedFiles, res.removedBytes, res.removedCompressedBytes, res.keptEntries));
        log.accept(dryRun ? "Dry run: nothing written." : String.format(Locale.ROOT, "Cleaned APK written: %s (%d -> %d B, unsigned)", out, res.inputSize, res.outputSize));
        return res;
    }

    static void write(RandomAccessFile f, List<Ent> keep, File out) throws IOException {
        try (CountingOut o = new CountingOut(new BufferedOutputStream(new FileOutputStream(out), 1 << 20))) {
            byte[] buf = new byte[1 << 16];
            for (Ent e : keep) {
                long dataStart = 0; byte[] mem = null;
                if (e.mem != null) { // noi dung moi: tinh lai crc / kich thuoc, giu nguyen kieu nen
                    CRC32 c = new CRC32(); c.update(e.mem); e.crc = c.getValue(); e.usize = e.mem.length;
                    mem = e.method == 0 ? e.mem : deflateRaw(e.mem); e.csize = mem.length;
                } else {
                    byte[] loc = new byte[30]; f.seek(e.locOff); f.readFully(loc);
                    if (u32(loc, 0) != 0x04034b50L) throw new IOException("Corrupt local header at " + e.sname);
                    dataStart = e.locOff + 30 + u16(loc, 26) + u16(loc, 28);
                }
                byte[] extra = new byte[0];
                if (e.method == 0) { // STORED: can le nhu zipalign
                    int align = e.sname.endsWith(".so") ? 4096 : 4;
                    long base = o.count + 30 + e.nameLen;
                    int need = (int) ((align - base % align) % align);
                    if (need != 0) {
                        if (need < 4) need += align;
                        extra = new byte[need];
                        extra[0] = 0x35; extra[1] = (byte) 0xD9; extra[2] = (byte) ((need - 4) & 0xFF); extra[3] = (byte) (((need - 4) >> 8) & 0xFF);
                    }
                }
                e.newLocOff = o.count; e.flags &= ~0x0008; // bo data descriptor: da ghi san crc/kich thuoc o header
                w32(o, 0x04034b50L); w16(o, e.needed); w16(o, e.flags); w16(o, e.method); w16(o, e.time); w16(o, e.date);
                w32(o, e.crc); w32(o, e.csize); w32(o, e.usize); w16(o, e.nameLen); w16(o, extra.length);
                o.write(e.name); o.write(extra);
                if (mem != null) o.write(mem, 0, mem.length);
                else {
                    f.seek(dataStart); long left = e.csize;
                    while (left > 0) { int n = f.read(buf, 0, (int) Math.min(buf.length, left)); if (n < 0) throw new EOFException(e.sname); o.write(buf, 0, n); left -= n; }
                }
            }
            long cdStart = o.count;
            for (Ent e : keep) {
                w32(o, 0x02014b50L); w16(o, e.madeBy); w16(o, e.needed); w16(o, e.flags); w16(o, e.method); w16(o, e.time); w16(o, e.date);
                w32(o, e.crc); w32(o, e.csize); w32(o, e.usize); w16(o, e.nameLen); w16(o, e.cdExtra.length); w16(o, e.comment.length);
                w16(o, e.diskStart); w16(o, e.intAttr); w32(o, e.extAttr); w32(o, e.newLocOff);
                o.write(e.name); o.write(e.cdExtra); o.write(e.comment);
            }
            long cdSize = o.count - cdStart;
            w32(o, 0x06054b50L); w16(o, 0); w16(o, 0); w16(o, keep.size()); w16(o, keep.size()); w32(o, cdSize); w32(o, cdStart); w16(o, 0);
        }
    }

    /** State shared by the per-entry rules of one run. */
    static final class Ctx {
        List<Pattern> prot = new ArrayList<>(), userProtect = new ArrayList<>(), junk = new ArrayList<>();
        Set<String> exact = new HashSet<>(), knownCrash = new HashSet<>(Arrays.asList(EXCLUDED_ROOT_CALLS)), keepAbi, refs = new HashSet<>();
        boolean dropBaseline, junkOn, aggressive, excludedApp, shieldDeep;
        boolean isUserProtected(String n) { for (Pattern p : userProtect) if (p.matcher(n).matches()) return true; return false; }
    }

    static String globToRegex(String g) {
        StringBuilder sb = new StringBuilder();
        for (char c : g.trim().toCharArray()) {
            if (c == '*') sb.append(".*"); else if (c == '?') sb.append('.');
            else { if ("\\.[]{}()+-^$|".indexOf(c) >= 0) sb.append('\\'); sb.append(c); }
        }
        return sb.toString();
    }

    /** Returns the reason a file is removed, or null to keep it. */
    static String reason(String n, Ctx c) {
        for (Pattern p : c.prot) if (p.matcher(n).matches()) return null;
        // CPU architecture filter (explicit user option, not a junk rule)
        if (c.keepAbi != null && n.startsWith("lib/")) {
            String[] sp = n.split("/");
            if (sp.length > 2 && !c.keepAbi.contains(sp[1])) return "other CPU lib";
        }
        if (c.dropBaseline && n.startsWith("assets/dexopt/")) return "baseline profile";
        if (!c.junkOn) return null;
        // folders that are only removed in aggressive mode
        if (c.aggressive) {
            if (n.equals("assets/audience_network.dex") || n.startsWith("assets/audience_network/")) return "audience_network";
        }
        // shield: resources, assets, native libs and anything the resource table points to are never "junk"
        if (n.startsWith("res/") || n.startsWith("assets/") || n.startsWith("lib/") || c.refs.contains(n)) return null;
        if (c.shieldDeep && n.indexOf('/') > 0 && !n.startsWith("META-INF/")) return null;
        // Files that made some apps crash (original patch exclusion list): kept, except in aggressive mode for apps that are not on the exclusion list.
        if (c.knownCrash.contains(n)) return c.aggressive && !c.excludedApp ? "known-sensitive library file (aggressive)" : null;
        // safe rules
        for (Pattern p : c.junk) if (p.matcher(n).matches()) return "junk pattern";
        if (c.exact.contains(n)) return "junk file name";
        if (n.startsWith("org/jacoco/")) return "junk folder org/jacoco/";
        if (n.startsWith("META-INF/maven/") || n.startsWith("META-INF/proguard/")) return "META-INF build leftovers";
        if (!c.aggressive) return null;
        // aggressive-only rules
        if (n.startsWith("kotlin/")) return "kotlin/ folder";
        for (String d : JUNK_DIRS) {
            if (d.equals("assets/dexopt/") || d.equals("org/jacoco/")) continue;
            if (n.startsWith(d)) return "junk folder " + d;
        }
        if (n.startsWith("META-INF/")) return "other META-INF";
        return null;
    }

    /** Package name from the binary AndroidManifest.xml (attribute "package" of the manifest element), or null. */
    static String readPackage(byte[] m) {
        if (m.length < 16 || u16(m, 0) != 0x0003) return null;
        String[] pool = null; int p = u16(m, 2);
        while (p + 8 <= m.length) {
            int type = u16(m, p), size = i32(m, p + 4); if (size <= 0) break;
            if (type == 0x0001 && pool == null) pool = readPool(m, p);
            if (type == 0x0102 && pool != null) {
                int ni = i32(m, p + 20); if (ni < 0 || ni >= pool.length || !"manifest".equals(pool[ni])) return null;
                int attrStart = u16(m, p + 24), attrSize = u16(m, p + 26), attrCount = u16(m, p + 28);
                for (int i = 0; i < attrCount; i++) {
                    int ao = p + 16 + attrStart + i * attrSize;
                    int ns = i32(m, ao), an = i32(m, ao + 4);
                    if (ns == -1 && an >= 0 && an < pool.length && "package".equals(pool[an])) {
                        int raw = i32(m, ao + 8); if (raw >= 0 && raw < pool.length) return pool[raw];
                    }
                }
                return null;
            }
            p += size;
        }
        return null;
    }

    /** Every zip path that the resource table points to (res files, raw files, xml, drawables...). */
    static Set<String> arscRefs(byte[] a, Set<String> zipNames) {
        if (a.length < 12 || u16(a, 0) != 0x0002) throw new IllegalArgumentException("invalid resources.arsc");
        Set<String> all = new HashSet<>(); String[] gpool = null;
        int total = (int) Math.min(u32(a, 4), a.length), p = u16(a, 2);
        while (p + 8 <= total) {
            int type = u16(a, p), size = i32(a, p + 4); if (size <= 0) throw new IllegalStateException("chunk size <= 0");
            if (type == 0x0001 && gpool == null) gpool = readPool(a, p);
            else if (type == 0x0200) {
                int q = p + u16(a, p + 2), end = p + size;
                while (q + 8 <= end) {
                    int t = u16(a, q), s = i32(a, q + 4); if (s <= 0) throw new IllegalStateException("inner chunk size <= 0");
                    if (t == 0x0201) collectRefs(a, q, gpool, all);
                    q += s;
                }
            }
            p += size;
        }
        Set<String> out = new HashSet<>(); for (String s : all) if (zipNames.contains(s)) out.add(s);
        return out;
    }

    static class CountingOut extends FilterOutputStream {
        long count;
        CountingOut(OutputStream o) { super(o); }
        @Override public void write(int b) throws IOException { out.write(b); count++; }
        @Override public void write(byte[] b, int off, int len) throws IOException { out.write(b, off, len); count += len; }
    }
}
