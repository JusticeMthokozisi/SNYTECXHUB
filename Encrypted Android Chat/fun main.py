fun main() {
    val security = SecurityManager()
    val chatHistory = mutableListOf<ChatMessage>()

    println("=== VS Code Secure Chat Demo ===")
    
    while (true) {
        print("\nEnter Message (or type 'quit'): ")
        val input = readLine() ?: ""

        if (input.lowercase() == "quit") break
        if (input.isBlank()) {
            println("Error: Cannot send empty message.")
            continue
        }

        try {
            // 1. PERFORM LOCAL ENCRYPTION
            val (cipherText, iv) = security.encrypt(input)
            
            // 2. SIMULATE RECEIVING/DECRYPTING
            val decryptedText = security.decrypt(cipherText, iv)

            // 3. UPDATE HISTORY
            val msg = ChatMessage("User1", cipherText, iv, decryptedText)
            chatHistory.add(msg)

            // 4. DISPLAY UI
            println("\n--- Chat History ---")
            chatHistory.forEach { 
                println("[${it.sender}]: ${it.decryptedDisplay}")
                println("  (Stored as: ${it.encryptedContent.take(15)}...)") 
            }

        } catch (e: Exception) {
            println("Critical Error during encryption: ${e.message}")
        }
    }
}