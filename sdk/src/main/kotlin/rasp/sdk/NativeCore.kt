package rasp.sdk

internal object NativeCore {
    init { System.loadLibrary("rasp") }
    @JvmStatic external fun run(signer: String?): String
}
