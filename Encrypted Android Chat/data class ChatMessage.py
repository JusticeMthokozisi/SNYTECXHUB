data class ChatMessage(
    val sender: String,
    val encryptedContent: String,
    val iv: String,
    val decryptedDisplay: String
)