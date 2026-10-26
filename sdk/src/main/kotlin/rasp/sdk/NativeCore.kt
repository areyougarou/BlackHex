package rasp.sdk

internal object NativeCore {
    val loadError: Throwable? = try { System.loadLibrary("blackhex"); null } catch (t: Throwable) { t }
    @JvmStatic external fun run(signer: String?): String
}
