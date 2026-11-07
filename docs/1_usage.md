# 🛠️ Using ReVanced CLI

Learn how to use ReVanced CLI.
The following examples will show you how to perform basic operations.
You can list patches, patch an app, uninstall, and install an app.

> [!NOTE]
> For demonstrative purposes, `-b` is used to
> bypass patches signature and build provenance verification for some commands.

## 🚀 Show all commands

```bash
java -jar revanced-cli.jar -h
```

## 📃 List patches

```bash
java -jar revanced-cli.jar list-patches --packages --versions --options -bp patches.rvp
```

## 💉 Patch an app

To patch an app using the default list of patches, use the `patch` command.

```bash
java -jar revanced-cli.jar patch -bp patches.rvp input.apk
```

You can also use multiple RVP files:

```bash
java -jar revanced-cli.jar patch -bp patches.rvp -bp another-patches.rvp input.apk
```

To change the default set of enabled or disabled patches, use the option `-e` or `-d` to enable or
disable specific patches.
You can use the `list-patches` command to see which patches are enabled by default.

To only enable specific patches, you can use the option `--exclusive` combined with `-e`.
Remember that the options `-e` and `-d` match the patch's name exactly. Here is an example:

```bash
java -jar revanced-cli.jar patch -bp patches.rvp --exclusive -e "Patch name" -e "Another patch name" input.apk
```

You can also use the options `--ei` or `--di` to enable or disable patches by their index.
This is useful, if two patches happen to have the same name, or if typing the names is too
cumbersome.
To know the indices of patches, use the command `list-patches`:

```bash
java -jar revanced-cli.jar list-patches -bp patches.rvp
```

Then you can use the indices to enable or disable patches:

```bash
java -jar revanced-cli.jar patch -bp patches.rvp --ei 123 --di 456 input.apk
```

You can combine the option `-e`, `-d`, `--ei`, `--di` and `--exclusive`. Here is an example:

```bash
java -jar revanced-cli.jar patch -bp patches.rvp --exclusive -e "Patch name" --ei 123 input.apk
```

> [!TIP]
> You can use the option `-i` to automatically install the patched app after patching.
> Make sure ADB is working:
>
> ```bash
>  adb shell exit
> ```


> [!TIP]
> You can use the option `--mount` to mount the patched app on top of the un-patched app.
> Make sure you have root permissions and the same app you are patching and mounting over is
> installed on your device:
>
> ```bash
> adb shell su -c exit
> adb install input.apk
> ```

Patches can have options you can set using the option `-O` alongside the option to include the patch
by name or index.
To know the options of a patch, use the option `--options` when listing patches:

```bash
java -jar revanced-cli.jar list-patches --options -bp patches.rvp
```

Each patch can have multiple options. You can set them using the option `-O`.
For example, to set the options for the patch with the name `Patch name`
with the key `key1` and `key2` to `value1` and `value2` respectively, use the following command:

```bash
java -jar revanced-cli.jar patch -bp patches.rvp -e "Patch name" -Okey1=value1 -Okey2=value2 input.apk
```

If you want to set the option value to `null`, you can omit the value:

```bash
java -jar revanced-cli.jar patch -bp patches.rvp -i "Patch name" -Okey1 input.apk
```

> [!WARNING]
> Option values are usually typed. If you set a value with the wrong type, the patch can fail.
> The value types can be seen when listing patches with the option `--options`.
>
> Example option values:
>
> - String: `string`
> - Boolean: `true`, `false`
> - Integer: `123`
> - Double: `1.0`
> - Float: `1.0f`
> - Long: `1234567890`, `1L`
> - List: `[item1,item2,item3]`
> - List of type `Any`: `[item1,123,true,1.0]`
> - Empty list of type `Any`: `[]`
> - Typed empty list: `int[]`
> - Typed and nested empty list: `[int[]]`
> - List with null value and two empty strings: `[null,\'\',\"\"]`
>
> Quotes and commas escaped in strings (`\"`, `\'`, `\,`) are parsed as part of the string.
> List items are recursively parsed, so you can escape values in lists:
>
> - Escaped integer as a string: `[\'123\']`
> - Escaped boolean as a string: `[\'true\']`
> - Escaped list as a string: `[\'[item1,item2]\']`
> - Escaped null value as a string: `[\'null\']`
> - List with an integer, an integer as a string and a string with a comma, and an escaped list: [
    `123,\'123\',str\,ing`,`\'[]\'`]
>
> Example command with an escaped integer as a string:
>
> ```bash
> java -jar revanced-cli.jar -bp patches.rvp -e "Patch name" -OstringKey=\'1\' input.apk
> ```

## 🧹 NEW SPECIAL COMMAND-IN-LINE

Extra options of the `patch` command added in this fork. They work on the APK file itself (zip level, no apktool and no aapt2), **before** the patches are applied, so the patches then run on the already cleaned APK. Using any option of this group turns that step on; without any of them `patch` behaves as before. If this step fails, the command stops and nothing is patched.

| Option | Value | What it does | Example |
|---|---|---|---|
| `--clean-safe` | none | Removes junk files that are safe to remove: licenses and notices, `.proto` files, tracker lists, version marker files of ad / analytics / Play Services libraries, `org/jacoco/`, `META-INF/maven` and `META-INF/proguard`. Files used by `res/`, `assets/`, `lib/` and by `resources.arsc` are never touched. | `--clean-safe` |
| `--clean-aggressive` | none | Also removes the risky group: library files known to crash some apps, `kotlin/`, `org/joda/`, `com/clevertap/`, `services/`, `assets/audience_network*` and the other `META-INF` entries. | `--clean-aggressive` |
| `--clean-protect` | comma separated paths or globs (`*` many characters, `?` one) | Paths the cleaning must never delete. Use it when an app breaks because a file is missing. | `--clean-protect play-services-base.properties,*.kotlin_module` |
| `--clean-keep-abi` | comma separated CPU ABIs | Keeps only these ABIs in `lib/`, removes the others. | `--clean-keep-abi armeabi-v7a` |
| `--clean-ads-assets` | none | Deletes `assets/Ads*` and `assets/*Ads*Configs.json`. | `--clean-ads-assets` |
| `--clean-manifest-ads` | none | Removes ad SDK permissions, services, receivers, providers, activities, activity aliases, meta-data and libraries from `AndroidManifest.xml`. | `--clean-manifest-ads` |
| `--clean-generic-perms` | none | Together with `--clean-manifest-ads`: also removes generic permissions (`CHANGE_NETWORK_STATE`, `CHANGE_WIFI_STATE`, ...). Risky: features that use them can crash. | `--clean-manifest-ads --clean-generic-perms` |
| `--clean-langs` | comma separated language codes | Keeps only these languages, removes the other translations. `en-US` and `en-rUS` mean `en` (all regions of a language are kept). | `--clean-langs en,vi` |
| `--clean-dpi` | comma separated densities: `ldpi` `mdpi` `tvdpi` `hdpi` `xhdpi` `xxhdpi` `xxxhdpi` or a number | Remove duplicate graphics: an image that exists in several screen densities keeps only the copy Android would pick for the given densities; the other copies and their files are removed. Resource ids do not change. | `--clean-dpi xxhdpi` or `--clean-dpi xhdpi,xxhdpi` or `--clean-dpi 420` |
| `--clean-png` | none | Re-compresses PNG files without losing quality. | `--clean-png` |
| `--clean-drop-baseline` | none | Also deletes `assets/dexopt/` (baseline profile). Startup can get slower. | `--clean-drop-baseline` |
| `--clean-dry-run` | none | Only lists what the cleaning would remove, writes nothing and does not patch. | `--clean-safe --clean-dry-run` |
| `--lower-sdk` | API level (a number) | Lowers `minSdkVersion` in `AndroidManifest.xml` to this number. It never raises it. Only the manifest is edited, the code is not changed. A warning is printed when the APK has dex files newer than Android 8 can read. | `--lower-sdk 26` |

`--purge` also deletes the temporary cleaned APK, together with the other temporary files.

Example with several of them (the value goes after a space, or after `=`):

```bash
java -jar revanced-cli.jar patch -bp patches.rvp --purge \
  --clean-safe --clean-keep-abi armeabi-v7a --clean-ads-assets --clean-manifest-ads \
  --clean-langs en,vi --clean-dpi xxhdpi --lower-sdk 26 input.apk
```

> [!TIP]
> Run it once with `--clean-dry-run` first (for example `--clean-safe --clean-langs en,vi --clean-dry-run`) to see the list of what would be removed.

> [!WARNING]
> `--clean-aggressive`, `--clean-generic-perms` and `--clean-dpi` can break or blur an app on some devices. `--lower-sdk` does not make the code compatible with older Android versions.

## 📦 Install an app manually

```bash
java -jar revanced-cli.jar utility install -a input.apk
```

> [!TIP]
> You can use the option `--mount` to mount the patched app on top of the un-patched app.
> Make sure you have root permissions and the same app you are patching and mounting over is
> installed on your device:
>
> ```bash
> adb shell su -c exit
> adb install input.apk
> ```

## 🗑️ Uninstall an app manually

Here `<package-name>` is the package name of the app you want to uninstall:

```bash
java -jar revanced-cli.jar utility uninstall --package-name <package-name>
```

If the app is mounted, you need to unmount it by using the option `--unmount`:

```bash
java -jar revanced-cli.jar utility uninstall --package-name <package-name> --unmount
```

> [!TIP]
> By default, the app is installed or uninstalled to the first connected device.
> You can append one or more devices by their serial to install or uninstall an app on your selected
> choice of devices:
>
> ```bash
> java -jar revanced-cli.jar utility uninstall --package-name <package-name> [<device-serial> ...]
> ```

## 🔐 Signature and build provenance verification

To increase confidence and security that the patches you are applying are from a trusted source
and have not been tampered with, artifacts such as the patches files
are signed with PGP by the respective author
and their provenance attested by the platform in which they are built.

ReVanced CLI currently supports build provenance verification for these platforms:

- GitHub

By default, ReVanced CLI requires additional inputs to verify the signature and provenance,
but to bypass these verifications, you can use the option `--bypass-verification` or `-b`
for each input of patches.

```bash
java -jar revanced-cli.jar patch -bp patches.rvp input.apk
```

To verify the signature and provenance, you need to provide the following options
for each input of patches:

- `--public-key-ring` or `-k`: Path to the PGP public key ring 
containing the public key of the author who signed the patches file
- `--signature` or `-s`: Path to the PGP signature file
- `--attestation` or `-a`: Path to the build provenance attestation file
- Additional verification options for the respective platform which produced the patches file:
    - GitHub:
        - `--repository` or `-r`: GitHub repository in the format 'owner/repo'

For example, to verify the signature and provenance of a patches file from GitHub
when using the `list-patches` command, use the following command:

```bash
java -jar revanced-cli.jar list-patches -p patches.rvp -k public-key-ring.gpg -s patches.rvp.asc -a patches.rvp.sigstore.json -r owner/repo
```
