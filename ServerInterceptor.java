
public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] Honest relay mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        // Honest relay - no modification
		System.out.println("Relaying from " + fromClient + " to client " + toClient + " : " + message);

        // Affichage déchiffré
        System.out.println("De " + fromClient + " à " + toClient + " : " + rot13(message));
        return message;
    }

    //on reprend l'implémentation de rot13, si l'attaquant connait d'un moyen ou d'un autre l'algorithme utilisé, il peut le réemployer facilement 
    private String rot13(String text) { 
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
