# Security policy

## Which versions get fixes

IntaktoFT is pre-1.0 and the public interface is still settling. Fixes land on the
latest released tag only. Before you report something, move to the newest tag on
[JitPack](https://jitpack.io/#areyougarou/IntaktoFT) and check that it still happens there.

| Version | Gets security fixes |
|---|---|
| Latest `0.2.x` tag | Yes |
| Anything older | No, upgrade first |

## How to report a vulnerability

Report it privately. Do not open a public issue, and do not describe the problem in a
pull request, a discussion or a commit message, because that hands a working attack to
everyone reading the repository.

Use GitHub's private channel: open the **Security** tab of
`github.com/areyougarou/IntaktoFT`, then **Report a vulnerability**. That opens a draft
only the maintainer can read.

Tell us, in the report:

- what an attacker gains (for example: a hook the checks miss, a repackaged APK that reads CLEAN, a crash you can trigger in a host app);
- the exact steps, the tool and its version, and the phone model and Android build you saw it on;
- the smallest proof you have. A log excerpt or a short script is enough. We do not need a weaponised exploit.

## What happens next

We aim to reply within 7 days and to agree a fix and a disclosure date with you. We credit
reporters who want the credit. We ask you to keep the detail private until the fixed tag
ships, so adopters can upgrade first.

## What is in scope

In scope: the free-tier library in this repository (the `sdk` module and the native code
under `native/`), and anything that lets an attacker tamper with or hook a host app without
IntaktoFT reporting it, or that makes IntaktoFT close or crash an honest app.

Out of scope: the paid tier (report those through the paid-tier channel), social engineering
of the maintainer, and findings that need a privileged attacker you already lost the phone to.

## One limit to keep in mind

IntaktoFT runs inside the app it protects, on a device the attacker may fully control. It
raises the cost of an attack and reports the attacks it is built to see. It is one layer,
not a guarantee. Keep the decisions that matter on your server.
