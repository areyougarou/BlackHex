# How to read a result

[Back to the README](../../README.md)

Every check answers one of three ways.
CLEAN: it looked and found nothing wrong.
DETECTED: it looked and found a real problem.
INCONCLUSIVE: it could not get an answer (a read failed or came back empty).

Only DETECTED closes the app. INCONCLUSIVE never does. The accepted cost is that an attacker
with root who blocks the reads a check needs is not stopped by that check. In `Mode.REPORT` the host
reads each signal's status, so it can tell INCONCLUSIVE apart from CLEAN and decide for itself.

A check is left out of the report only for a fact known before anything is read: the two APK
file checks for an app that ships inside the system image, and the 4 instrumentation checks built
only for arm64 phones (other chip types skip them). Left out means less coverage, not a clean
result.
