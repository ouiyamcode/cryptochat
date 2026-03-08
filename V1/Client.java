import java.io.*;
import java.net.*;
import java.util.Scanner;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;


public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8888;

    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;
    private Interceptor interceptor;
    private volatile boolean running;

    private String password;
    private SecretKeySpec sessionKey;

    public Client() {
        this.interceptor = new Interceptor();
        this.running = true;
    }

    public static void main(String[] args) {
        System.out.println("Starting client ...");
        // vérification qu'on a bien qu'un seul argument en ligne de commande 
        if (args.length != 1){
            System.err.println("Usage: java Client.java <password>");
            return;
        }
        // vérification de la conformité du mot de passe
        if (!isValidPassword(args[0])){
            System.err.println("Entrez un nouveau mot de passe en argument");
            return;
        }
        Client client = new Client();
        // on assigne le mot de passe au client
        client.password = args[0];
        client.start();
    }

    public void start() {
        System.out.println("=== Crypto Chat Client ===");
        System.out.println("Connecting to server at " + SERVER_HOST + ":" + SERVER_PORT + "...");

        try {
            socket = new Socket(SERVER_HOST, SERVER_PORT);
            System.out.println("Connected to server successfully!\n");

            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            output = new PrintWriter(socket.getOutputStream(), true);

            // Wait for server's READY signal (sent when both clients are connected)
            System.out.println("Waiting for other client to connect...");
            String readySignal = input.readLine();
            if (!"READY".equals(readySignal)) {
                throw new IOException("Expected READY signal, got: " + readySignal);
            }
            System.out.println("Both clients connected!\n");

            System.out.println("--- Handshake Phase ---");
            interceptor.onHandshake(input, output);
            System.out.println("--- Handshake Complete ---\n");

            System.out.println("--- Key derivation phase ---");
            sessionKey = deriveKey128(password);
            System.out.println("Clef dérivée (base64): " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
            System.out.println("--- Key derivation complete ---");


            System.out.println("Chat session started!");
            System.out.println("Type your messages and press Enter to send.");
            System.out.println("Type 'exit' to quit.\n");

            Thread receiverThread = new Thread(new MessageReceiver());
            receiverThread.start();

            handleUserInput();

        } catch (IOException e) {
            System.err.println("Connection error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }

    private void handleUserInput() {
        Scanner scanner = new Scanner(System.in);

        try {
            while (running) {
                String message = scanner.nextLine();

                if (message.equalsIgnoreCase("exit")) {
                    System.out.println("Disconnecting...");
                    running = false;
                    break;
                }

                if (message.trim().isEmpty()) {
                    continue;
                }

                String processedMessage = interceptor.beforeSend(message);
                output.println(processedMessage);
                System.out.println("You: " + message);
            }
        } finally {
            scanner.close();
        }
    }

    private void cleanup() {
        running = false;

        try {
            if (input != null) input.close();
            if (output != null) output.close();
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (IOException e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }

        System.out.println("Disconnected from server.");
    }

    // fonction pour vérifier si le password est conforme
    private static boolean isValidPassword(String pass){
        // vérifie problème de mauvaise allocation de valeur
        if(pass == null){
            System.out.println("Veuillez réessayer svp !");
            return false;
        }
        // vérifie si bien sans espaces
        if(!pass.equals(pass.trim())){
            System.out.println("Veuillez réessayer sans espaces svp !");
            return false;
        }

        int len = pass.length();
        // vérifie si le mot de passe a min 15 caractères et max 128
        if(len < 15 || len > 128){
            System.out.println("Veuillez réessayer avec minimum 15 caractères et maximum 128 svp !");
            return false;
        }

        boolean lower = false;
        boolean upper = false;
        boolean digit = false;

        // vérifie présence d'au moins 1 maj, 1 min et 1 chiffre
        for(int i = 0; i < pass.length(); i++){
            char c = pass.charAt(i);
            if(Character.isLowerCase(c)){
                lower = true;
            }
            else if(Character.isUpperCase(c)){
                upper = true;
            }
            else if(Character.isDigit(c)){
                digit = true;
            }
        }

        if(lower == false || upper == false || digit == false){
            System.out.println("Veuillez réessayer avec une minuscule, une majuscule et un chiffre minimum svp !");
            return false;
        }

        return true;
    }

    // dérive une clef de 128 bits grâce aux 16 premiers octets tronqués d'un hash SHA2-256
    private static SecretKeySpec deriveKey128(String password){
        try{
            // création d'un objet qui peut calculer un hash SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // convertit le mot de passe en octets (UTF-8) et calcule le hash => 32 octets
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            // tronque les 16 premiers octets => 128 bits 
            byte[] keyBytes = Arrays.copyOf(hash, 16);
            // on renvoie les 16 octets comme clef AES utilisable plus tard pour chiffrer
            return new SecretKeySpec(keyBytes, "AES");
        }
        catch(Exception e){
            throw new RuntimeException("Dérivation de clef échouée", e);
        }
    }

    private class MessageReceiver implements Runnable {
        @Override
        public void run() {
            try {
                String receivedMessage;

                while (running && (receivedMessage = input.readLine()) != null) {
                    String decryptedMessage = interceptor.afterReceive(receivedMessage);
                    System.out.println("Other: " + decryptedMessage);
                }

            } catch (IOException e) {
                if (running) {
                    System.err.println("Error receiving message: " + e.getMessage());
                }
            }
        }
    }
}
