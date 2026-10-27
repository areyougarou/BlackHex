package io.github.areyougarou.blackhex

import java.io.ByteArrayInputStream
import java.io.EOFException
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

    fun verify(f: FileChannel, known: Set<String>, targetSdk: Int): ApkVerdict {
        if (known.isEmpty()) return ApkVerdict(Status.INCONCLUSIVE, null, "no signer from Android to compare")
        val (eocd, eocdOff) = endRecord(f) ?: return ApkVerdict(Status.INCONCLUSIVE, null, "no ZIP end record")
        val cdOff = le32(eocd, 16).toLong() and 0xffffffffL
        val cdSize = le32(eocd, 12).toLong() and 0xffffffffL
        if (cdOff + cdSize != eocdOff || cdOff < 32) return ApkVerdict(Status.INCONCLUSIVE, null, "unexpected ZIP layout")
        val foot = read(f, cdOff - 24, 24)
        if (String(foot, 8, 16, Charsets.US_ASCII) != "APK Sig Block 42") return if (targetSdk >= 30)
            ApkVerdict(Status.DETECTED, null, "no v2/v3 signing block: the APK is signed with v1 only, which Android refuses for targetSdkVersion $targetSdk")
        else ApkVerdict(Status.INCONCLUSIVE, null, "signed with v1 only, which Android accepts below targetSdkVersion 30; this check reads only v2/v3 signers")
        val blockSize = ByteBuffer.wrap(foot).order(ByteOrder.LITTLE_ENDIAN).long
        if (blockSize < 24 || blockSize > 16L * CHUNK || blockSize + 8 > cdOff)
            return ApkVerdict(Status.INCONCLUSIVE, null, "implausible signing block size")
        val blockStart = cdOff - blockSize - 8
        val head = read(f, blockStart, 8)
        if (le(head).long != blockSize) return ApkVerdict(Status.INCONCLUSIVE, null, "signing block sizes do not match")
        val pairs = read(f, blockStart + 8, (blockSize - 24).toInt())
        val blocks = try { idValues(pairs) } catch (t: RuntimeException) {
            return ApkVerdict(Status.INCONCLUSIVE, null, "unparseable signing block")
        }
        val entries = try {
            listOf(V31 to "v3.1", V3 to "v3", V2 to "v2").flatMap { (id, scheme) -> blocks[id]?.let { entries(it, scheme, id != V2) }.orEmpty() }
        } catch (t: RuntimeException) {
            return ApkVerdict(Status.INCONCLUSIVE, null, "unparseable signer")
        }
        if (entries.isEmpty()) return ApkVerdict(Status.INCONCLUSIVE, null, "no v2/v3 signer")
        val e = entries.firstOrNull { it.signer in known } ?: return ApkVerdict(Status.DETECTED, entries.first().signer,
            "no signing entry in the file carries a signer Android reports: file=${entries.joinToString(",") { it.signer.take(16) }} " +
                "android=${known.joinToString(",") { it.take(16) }}")
        val (scheme, signedData, sigs, publicKey, digests, certDer, signer) = e
        val alg = algs.firstOrNull { a -> a.id in sigs }
            ?: return ApkVerdict(Status.INCONCLUSIVE, null, "$scheme: no supported signature algorithm")
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
        val actual = contentDigest(f, alg.digest, blockStart, cdOff, eocdOff, eocd)
        if (!actual.contentEquals(expected))
            return ApkVerdict(Status.DETECTED, signer, "$scheme: file contents differ from what was signed")
        return ApkVerdict(Status.CLEAN, signer, "$scheme: contents match the signature, signer ${signer.take(16)}")
    }

    fun entryNames(f: FileChannel): List<String> {
        val (eocd, eocdOff) = requireNotNull(endRecord(f)) { "no ZIP end record" }
        val cdOff = le32(eocd, 16).toLong() and 0xffffffffL
        require(cdOff + (le32(eocd, 12).toLong() and 0xffffffffL) == eocdOff) { "unexpected ZIP layout" }
        val cd = le(read(f, cdOff, le32(eocd, 12)))
        val names = ArrayList<String>()
        while (cd.remaining() >= 46 && cd.getInt(cd.position()) == 0x02014b50) {
            val p = cd.position()
            val n = cd.getShort(p + 28).toInt() and 0xffff
            names += String(ByteArray(n).also { cd.position(p + 46); cd.get(it) }, Charsets.UTF_8)
            cd.position(p + 46 + n + (cd.getShort(p + 30).toInt() and 0xffff) + (cd.getShort(p + 32).toInt() and 0xffff))
        }
        require("AndroidManifest.xml" in names) { "no AndroidManifest.xml in the ZIP directory" }
        return names
    }

    private fun endRecord(f: FileChannel): Pair<ByteArray, Long>? {
        val size = f.size()
        val tail = read(f, size - minOf(size, 65557L), minOf(size, 65557L).toInt())
        val e = (tail.size - 22 downTo 0).firstOrNull {
            le32(tail, it) == 0x06054b50 && it + 22 + ((tail[it + 20].toInt() and 0xff) or ((tail[it + 21].toInt() and 0xff) shl 8)) == tail.size
        } ?: return null
        return tail.copyOfRange(e, tail.size) to size - tail.size + e
    }

    private data class Entry(
        val scheme: String, val signedData: ByteArray, val sigs: Map<Int, ByteArray>, val publicKey: ByteArray,
        val digests: Map<Int, ByteArray>, val cert: ByteArray, val signer: String,
    )

    private fun entries(value: ByteArray, scheme: String, v3: Boolean): List<Entry> {
        val out = ArrayList<Entry>()
        val signers = le(value).lp()
        while (signers.hasRemaining()) {
            val s = signers.lp()
            val signedData = s.lp().bytes()
            if (v3) { s.int; s.int }
            val sigs = HashMap<Int, ByteArray>()
            val ss = s.lp()
            while (ss.hasRemaining()) { val one = ss.lp(); sigs[one.int] = one.lp().bytes() }
            val publicKey = s.lp().bytes()
            val sd = le(signedData)
            val digests = HashMap<Int, ByteArray>()
            val ds = sd.lp()
            while (ds.hasRemaining()) { val d = ds.lp(); digests[d.int] = d.lp().bytes() }
            val cs = sd.lp()
            if (!cs.hasRemaining()) continue
            val cert = cs.lp().bytes()
            out += Entry(scheme, signedData, sigs, publicKey, digests, cert, hex(MessageDigest.getInstance("SHA-256").digest(cert)))
        }
        return out
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
                        fill(ch, buf, pos).flip()
                        out[i] = chunk(md, buf)
                        progress()
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

    private fun fill(ch: FileChannel, b: ByteBuffer, pos: Long): ByteBuffer {
        while (b.hasRemaining()) if (ch.read(b, pos + b.position()) < 0) throw EOFException()
        return b
    }

    private fun read(ch: FileChannel, pos: Long, n: Int): ByteArray = fill(ch, ByteBuffer.allocate(n), pos).array()

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
