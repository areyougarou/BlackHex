> [!IMPORTANT]
> **Why IntaktoFT?**
>
> Protecting your app doesn't have to be a nightmare.
>
> Every day, a new adblock gets released, a new cheat, a new Frida method. All free and open source.
> Meanwhile, cybersecurity giants gatekeep protection behind absurd prices.
>
> The only options for indie developers are to lose to attackers, or to shrink their margins.
>
> Unfair? I agree.
>
> This is why we're releasing IntaktoFT.

~ IntaktoFT

Free Android RASP (runtime application self-protection) library. The free tier is open source. 
It answers two questions: were your app's files changed (repackaging), and is someone hooking the running code (instrumentation)?
If either answer is yes, it stops the app.

~ What it offers and will never change

1. **It doesn't collect data**
   Sending data to third parties requires you to fill in the Google Play data form, provide privacy contracts, ask for your users' permission...
   We don't collect data, so none of that headache.
2. **Effortless setup**
   One line, `Intakto.check(this)`, and you're done.
   No API key, no dashboard, no sign-up. Everything IntaktoFT needs is already inside your APK.
3. **Riskless**
   We use checks that produce zero false positives, crashes or slowdown.
   Every check is tested across devices, Android versions and app types ([where we test it](#tested-on)).
   If a check fires, someone is trying to harm your app.
   If one ever misfires on a phone we have not seen, switch to report-only: `Intakto.check(this, Mode.REPORT)` hands the result to your callback and never closes the app.
4. **Free**
   Apache 2.0, commercial apps included, no account, no device limit.


~ Who is this for
- **Indie developers** who want anti-mod and tamper detection without a sales call or a server bill.
- **Game studios** losing money to cheats and to paid content unlocked for free.
- **Free, ad-supported apps** whose only income is the ads a modded copy strips out.


~ Why is it open source? Can't the attackers break into it?
The free tier is transparent and accessible, so that you can see what gets added to your app.
But for the attacker knowing the defense is not enough, they need actual efforts and knowledge to break into it. And some of the checks are not easy to fool.
Multiple apps who adopted IntaktoFT reported us that, even with the open sourced version, they noticed a visible reduction in offensive behavior.
The paid tier is closed and obfuscated and is aimed at fighting profitable frauds and mass attacks. Not information you need, but the shareholders forced me to state it loud and clear.


~ Why no root, emulator or VPN checks?
Because most users who have them are not harmful. You'd end up losing real traffic witch-hunting a weak signal. 
Those checks are a liability, not a feature.
Instead we only look for repackaging and instrumentation: attacks beyond any reasonable doubt.


~ How is IntaktoFT different from other free RASPs?
Other free RASPs collect data from your users' phones. Their root and hook checks have flagged genuine users.
IntaktoFT flags only users who are actively harming your app, from values that prove instrumentation or repackaging. We don't chase weak signals or witch-hunt real users.
A specialist beats a generalist. Google won by showing only results. Facing third-stage lung cancer, you would pick the oncologist who treats exactly that.
So IntaktoFT stays narrow on purpose: zero false positives, retested against every new release of the tools below, and nothing sent anywhere.


~ What IntaktoFT catches

**To validate IntaktoFT, we measured it against all available off-the-shelf tools an attacker can use to break into your app.**
Most tools not listed here are forks or wrappers of the same engines: Frida, Xposed-style frameworks such as LSPosed, and repackagers such as LSPatch.

| Tool | Engine it runs | Check that catches it | How |
|---|---|---|---|
| frida-server 17.23.3 | Frida 17.23.3 agent | `FRIDA_AGENT_IN_MEMORY` | its agent, loaded from memory, exports `frida_agent_main` |
| frida-inject 17.23.3 | Frida 17.23.3 agent | `FRIDA_AGENT_IN_MEMORY` | same |
| StealthFrida 1.0 | Frida 17.8.2 agent | `FRIDA_AGENT_IN_MEMORY` | same |
| Morphida 17.24.3 | Frida 17.24.3 agent | `FRIDA_AGENT_IN_MEMORY` | same |
| ReShift 1.1.2 | Frida 17.24.3 agent | `FRIDA_AGENT_IN_MEMORY` | same |
| Florida 17.9.1 | Frida 17.9.1 agent | `DISGUISED_LIBRARY_IN_MEMORY` | its agent sits in a memfd named `jit-cache` |
| florida-zygisk 17.24.3 | Frida 17.24.3 agent | `DISGUISED_LIBRARY_IN_MEMORY` | same |
| MagiskHluda 17.6.2 | Frida 17.6.2 agent | `DISGUISED_LIBRARY_IN_MEMORY` | same |
| Rusda 17.23.1 | Frida 17.23.1 agent | `DISGUISED_LIBRARY_IN_MEMORY` | same |
| strongR-frida 16.5.6 | Frida 16.5.6 agent | `DISGUISED_LIBRARY_IN_MEMORY` | same |
| FreeDaah 17.19.0 | Frida 17.19.0 agent | `DISGUISED_LIBRARY_IN_MEMORY` | same |
| phantom-frida 17.16.4 | Frida 17.16.4 agent | `DISGUISED_LIBRARY_IN_MEMORY` | its agent sits in a memfd named `jit-code-cache` |
| Frida Gadget 17.23.3, added to the APK | Frida 17.23.3 gadget | `OPCODE_TRAMPOLINE` | when it hooks a watched system function: a jump at the function's start that the file on disk does not have |
| ZygiskFrida 1.9.0 | Frida gadget | `LIB_FROM_ROOT_PATH` | its loader runs from its root module folder |
| LSPosed (Vector) | Xposed-style framework | `LIB_FROM_ROOT_PATH` | its loader runs from its own root module folder, which it loads only into the apps it targets |
| LSPatch | repackager | `TAMPER_APK_CONTENT`, `TAMPER_SIGNING_BLOCK`, `TAMPER_REPACKAGER` | the rebuilt APK no longer matches the signer Android has on file, and it carries LSPatch's own files |
| App Cloner | repackager | `TAMPER_REPACKAGER` | the APK carries App Cloner's own files |

Every result, with the phone and Android build it ran on: [test results](TEST_RESULTS.md).
After implementing IntaktoFT, attacking your app will only be possible through custom tools, which considerably raises the attacker's entry barrier and cost.


~ Get started

IntaktoFT needs `minSdk 26` (Android 8.0) or higher. Add JitPack and the library, then call `Intakto.check(this)` in `Application.onCreate()`:

```kotlin
// settings.gradle.kts, inside dependencyResolutionManagement { repositories { ... } }
maven { url = uri("https://jitpack.io") }

// app/build.gradle.kts, inside dependencies { ... }
implementation("com.github.areyougarou:IntaktoFT:v0.2.1")
```

- [Integration guide](docs/guides/integration.md): the one-line setup, report mode, callbacks and cost.
- [Build from source](docs/guides/build.md).


<a id="tested-on"></a>
~ Where we test it

Our main goal during production was to aim for 0% disruption caused to real users (false positives, crashes, slowdowns, issues of any kind).
To achieve that, IntaktoFT has been (and keeps on being) tested on a vast number of devices: Android 10 to 17, all major phone manufacturers, custom ROMs, all app types.
We allowed honest debugging apps that ship their own hooking SDKs, such as ShadowHook and ByteHook, so you can add IntaktoFT next to the SDKs you already use.
The result is zero false positives. Like a spam filter that never buries a genuine email, IntaktoFT never closes the app on a genuine user.


~ Who is this not for
Apps suffering fake accounts, bonus abuse, referral farming, automation and MITM.
These issues mostly affect fintech, crypto, web3, social media, dating, online gambling and betting, e-commerce and marketplaces, ticketing and resale, streaming, gig and delivery, loyalty and rewards programs, MMORPGs and competitive games.
Even though IntaktoFT still visibly reduces these attack classes (mostly performed through instrumentation), a more specialized and protected solution is suggested.
If you're among these, contact us to see if you qualify for the commercial solutions: Intakto paid tier (link coming soon).


~ What it checks for

- [How to read a result](docs/checks/README.md): CLEAN, DETECTED or INCONCLUSIVE, and which one closes the app.
- [App integrity](docs/checks/app-integrity.md): the installed app files are intact, signed by the key Android reports for the app, and not renamed or cloned.
- [Instrumentation](docs/checks/instrumentation.md): someone is hooking or injecting code into your running app.

IntaktoFT actively hunts only for values that can be confirmed without server verdicts.
Device fingerprint, promo abuse and coordinated actions are **not included** in the free tier because they would violate this exact principle.
