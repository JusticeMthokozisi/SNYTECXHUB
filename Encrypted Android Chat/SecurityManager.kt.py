import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecurityManager {
    private val key: SecretKey

    init {
        // In Android, you'd generate this inside the "AndroidKeyStore"
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        key = keyGen.generateKey()
    }

    fun encrypt(plainText: String): Pair<String, String> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        
        val iv = cipher.iv // The Initialization Vector (needed for decryption)
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())
        
        return Base64.getEncoder().encodeToString(encryptedBytes) to 
               Base64.getEncoder().encodeToString(iv)
    }

    fun decrypt(encryptedText: String, ivString: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = Base64.getDecoder().decode(ivString)
        val spec = GCMParameterSpec(128, iv)
        
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val decodedBytes = Base64.getDecoder().decode(encryptedText)
        return String(cipher.doFinal(decodedBytes))
    }
}