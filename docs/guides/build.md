# Build

[Back to the README](../../README.md)

Android library module (`:sdk`), `minSdk 26`, `compileSdk 35`. One AAR carries the native
library for all four chip types (arm64-v8a, armeabi-v7a, x86 and x86_64) in `lib/`, so Play
delivers each phone only its own copy. Requires the Android NDK (see `sdk/build.gradle.kts` for
the pinned version).

```
./gradlew :sdk:assembleRelease
```
