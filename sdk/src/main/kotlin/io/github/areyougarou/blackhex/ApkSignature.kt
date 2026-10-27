package io.github.areyougarou.blackhex

import android.os.Build
import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

internal class ApkVerdict(val status: Status, val signer: String?, val detail: String)

internal object ApkSignature {

    private const val V2 = 0x7109871a
    private const val V3 = 0xf05368c0.toInt()
    private const val V31 = 0x1b93ad61
    private const val CHUNK = 1 shl 20

    private class Alg(val id: Int, val jca: String, val key: String, val digest: String, val pss: PSSParameterSpec? = null)

    private val algs = listOf(
        Alg(0x0103, "SHA256withRSA", "RSA", "SHA-256"),
        Alg(0x0201, "SHA256withECDSA", "EC", "SHA-256"),
        Alg(0x0101, "SHA256withRSA/PSS", "RSA", "SHA-256", PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
        Alg(0x0301, "SHA256withDSA", "DSA", "SHA-256"),
        Alg(0x0104, "SHA512withRSA", "RSA", "SHA-512"),
        Alg(0x0202, "SHA512withECDSA", "EC", "SHA-512"),
        Alg(0x0102, "SHA512withRSA/PSS", "RSA", "SHA-512", PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)),
    )

    fun verify(path: String, sdk: Int = Build.VERSION.SDK_INT): ApkVerdict = RandomAccessFile(path, "r").use { f ->
        val size = f.length()
        val tail = ByteArray(minOf(size, 65557L).toInt())
        f.seek(size - tail.size); f.readFully(tail)
        val e = (tail.size - 22 downTo 0).firstOrNull { le32(tail, it) == 0x06054b50 }
            ?: return ApkVerdict(Status.INCONCLUSIVE, null, "no ZIP end record")
        val eocd = tail.copyOfRange(e, tail.size)
        val eocdOff = size - tail.size + e
        val cdOff = le32(eocd, 16).toLong() and 0xffffffffL
        val cdSize = le32(eocd, 12).toLong() and 0xffffffffL
        if (cdOff + cdSize != eocdOff || cdOff < 32) return ApkVerdict(Status.INCONCLUSIVE, null, "unexpected ZIP layout")
        val foot = ByteArray(24).also { f.seek(cdOff - 24); f.readFully(it) }
        if (String(foot, 8, 16, Charsets.US_ASCII) != "APK Sig Block 42")
            return ApkVerdict(Status.INCONCLUSIVE, null, "no v2/v3 signing block (v1 only)")
        val blockSize = ByteBuffer.wrap(foot).order(ByteOrder.LITTLE_ENDIAN).long
        if (blockSize < 24 || blockSize > 16L * CHUNK || blockSize + 8 > cdOff)
            return ApkVerdict(Status.INCONCLUSIVE, null, "implausible signing block size")
        val blockStart = cdOff - blockSize - 8
        val head = ByteArray(8).also { f.seek(blockStart); f.readFully(it) }
        if (le(head).long != blockSize) return ApkVerdict(Status.INCONCLUSIVE, null, "signing block sizes do not match")
        val pairs = ByteArray((blockSize - 24).toInt()).also { f.seek(blockStart + 8); f.readFully(it) }
        val blocks = try { idValues(pairs) } catch (t: RuntimeException) {
            return ApkVerdict(Status.INCONCLUSIVE, null, "unparseable signing block")
        }
        val chosen = try { choose(blocks, sdk) } catch (t: RuntimeException) {
            return ApkVerdict(Status.INCONCLUSIVE, null, "unparseable signer")
        } ?: return ApkVerdict(Status.INCONCLUSIVE, null, "no v2/v3 signer for SDK $sdk")
        val (scheme, signedData, sigs, publicKey) = chosen
        val alg = algs.firstOrNull { a -> a.id in sigs }
            ?: return ApkVerdict(Status.INCONCLUSIVE, null, "$scheme: no supported signature algorithm")
        val digests = HashMap<Int, ByteArray>()
        val certs = ArrayList<ByteArray>()
        try {
            val sd = le(signedData)
            val ds = sd.lp()
            while (ds.hasRemaining()) { val d = ds.lp(); digests[d.int] = d.lp().bytes() }
            val cs = sd.lp()
            while (cs.hasRemaining()) certs += cs.lp().bytes()
        } catch (t: RuntimeException) {
            return ApkVerdict(Status.INCONCLUSIVE, null, "$scheme: unparseable signed data")
        }
        val certDer = certs.firstOrNull() ?: return ApkVerdict(Status.INCONCLUSIVE, null, "$scheme: no certificate")
        val signer = hex(MessageDigest.getInstance("SHA-256").digest(certDer))
        val key = KeyFactory.getInstance(alg.key).generatePublic(X509EncodedKeySpec(publicKey))
        val ok = Signature.getInstance(alg.jca).run {
            initVerify(key)
            alg.pss?.let { setParameter(it) }
            update(signedData)
            verify(sigs.getValue(alg.id))
        }
        if (!ok) return ApkVerdict(Status.DETECTED, signer, "$scheme: signature over the signed data is invalid")
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(certDer))
        if (!cert.publicKey.encoded.contentEquals(publicKey))
            return ApkVerdict(Status.DETECTED, signer, "$scheme: certificate does not carry the signing key")
        val expected = digests[alg.id] ?: return ApkVerdict(Status.INCONCLUSIVE, signer, "$scheme: no content digest")
        val actual = contentDigest(f.channel, alg.digest, blockStart, cdOff, eocdOff, eocd)
        if (!actual.contentEquals(expected))
            return ApkVerdict(Status.DETECTED, signer, "$scheme: file contents differ from what was signed")
        ApkVerdict(Status.CLEAN, signer, "$scheme: contents match the signature, signer ${signer.take(16)}")
    }

    private data class Chosen(val scheme: String, val signedData: ByteArray, val sigs: Map<Int, ByteArray>, val publicKey: ByteArray)

    private fun choose(blocks: Map<Int, ByteArray>, sdk: Int): Chosen? {
        if (sdk >= 33) blocks[V31]?.let { v -> signer(v, true, sdk)?.let { return it.copy(scheme = "v3.1") } }
        if (sdk >= 28) blocks[V3]?.let { v -> signer(v, true, sdk)?.let { return it.copy(scheme = "v3") } }
        return blocks[V2]?.let { v -> signer(v, false, sdk)?.copy(scheme = "v2") }
    }

    private fun signer(value: ByteArray, v3: Boolean, sdk: Int): Chosen? {
        val signers = le(value).lp()
        while (signers.hasRemaining()) {
            val s = signers.lp()
            val signedData = s.lp().bytes()
            if (v3) { val min = s.int; val max = s.int; if (sdk < min || sdk > max) continue }
            val sigs = HashMap<Int, ByteArray>()
            val ss = s.lp()
            while (ss.hasRemaining()) { val one = ss.lp(); sigs[one.int] = one.lp().bytes() }
            return Chosen("", signedData, sigs, s.lp().bytes())
        }
        return null
    }

    private fun idValues(pairs: ByteArray): Map<Int, ByteArray> {
        val b = le(pairs)
        val out = HashMap<Int, ByteArray>()
        while (b.remaining() >= 12) {
            val len = b.long
            require(len in 4..b.remaining().toLong())
            val id = b.int
            out[id] = ByteArray((len - 4).toInt()).also { b.get(it) }
        }
        return out
    }

    private fun contentDigest(ch: FileChannel, alg: String, blockStart: Long, cdOff: Long, eocdOff: Long, eocd: ByteArray): ByteArray {
        val patched = eocd.copyOf().also { le(it).putInt(16, blockStart.toInt()) }
        val chunks = listOf(0L to blockStart, cdOff to eocdOff).flatMap { (a, b) ->
            (a until b step CHUNK.toLong()).map { it to minOf(CHUNK.toLong(), b - it).toInt() }
        }
        val out = arrayOfNulls<ByteArray>(chunks.size)
        val next = AtomicInteger()
        val threads = minOf(Runtime.getRuntime().availableProcessors(), 4)
        val pool = Executors.newFixedThreadPool(threads)
        try {
            pool.invokeAll(List(threads) {
                Callable {
                    val md = MessageDigest.getInstance(alg)
                    val buf = ByteBuffer.allocateDirect(CHUNK)
                    while (true) {
                        val i = next.getAndIncrement()
                        if (i >= chunks.size) break
                        val (pos, n) = chunks[i]
                        buf.clear().limit(n)
                        while (buf.hasRemaining()) if (ch.read(buf, pos + buf.position()) < 0) throw EOFException()
                        buf.flip()
                        out[i] = chunk(md, buf)
                    }
                }
            }).forEach { it.get() }
        } finally { pool.shutdown() }
        val top = MessageDigest.getInstance(alg)
        top.update(0x5a.toByte()); top.update(u32(chunks.size + 1))
        out.forEach { top.update(it!!) }
        top.update(chunk(MessageDigest.getInstance(alg), ByteBuffer.wrap(patched)))
        return top.digest()
    }

    private fun chunk(md: MessageDigest, data: ByteBuffer): ByteArray {
        md.update(0xa5.toByte()); md.update(u32(data.remaining())); md.update(data)
        return md.digest()
    }

    private fun le(b: ByteArray): ByteBuffer = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)

    private fun ByteBuffer.lp(): ByteBuffer {
        val n = int
        require(n in 0..remaining())
        val s = slice().order(ByteOrder.LITTLE_ENDIAN)
        s.limit(n)
        position(position() + n)
        return s
    }

    private fun ByteBuffer.bytes(): ByteArray = ByteArray(remaining()).also { get(it) }

    private fun le32(b: ByteArray, off: Int): Int = ByteBuffer.wrap(b, off, 4).order(ByteOrder.LITTLE_ENDIAN).int

    private fun u32(v: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()

}
