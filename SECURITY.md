# Security policy

## Report a vulnerability privately

Found a way past IntaktoFT, or a way to make it close or crash an honest app? Please don't open a public issue. A public issue hands the attack to everyone before adopters can update.

Report it here instead: open the **Security** tab of this repo, then **Report a vulnerability**. Only the maintainer can read it.

Please include:
- what an attacker gets: for example a hook the checks miss, a repackaged APK that reads CLEAN, or a crash you can trigger in a host app;
- the steps, the tool and its version, and the phone model and Android build;
- the smallest proof you have. A log excerpt or a short script is enough.

## What happens next

We reply within 7 days, and agree on a fix and a disclosure date with you. If you want credit, you get it. Please keep the details private until the fixed version is out, so adopters can update first.

## Which versions get fixes

Only the latest one. IntaktoFT is still before 1.0. Before you report, check that the problem still happens on the newest tag on [JitPack](https://jitpack.io/#areyougarou/IntaktoFT).

## What's in scope

This repo: the `sdk` module and the native code in `native/`. That means anything that lets an attacker tamper with or hook an app without IntaktoFT reporting it, and anything that makes IntaktoFT close or crash an honest app.

Not in scope: the paid tier, which has its own channel, and attempts to trick the maintainer.
