import javax.net.ssl.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Mac; // Para HMAC
import javax.crypto.spec.SecretKeySpec; // Para crear la clave HMAC

public class cliente {

    private static final String HMAC_KEY = "clave_secreta"; // Debe coincidir con el del servidor

    public static void main(String[] args) {
        try {
            // Crear conexión SSL
            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 3343);

            // Crear flujos de entrada y salida
            PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Crear un scanner para leer entrada del usuario
            Scanner scanner = new Scanner(System.in);

            // Solicitar username y contraseña
            System.out.print("Introduce tu username: ");
            String username = scanner.nextLine();
            System.out.print("Introduce tu contraseña: ");
            String password = scanner.nextLine();

            // Generar un nonce aleatorio
            String nonce = generateNonce();

            // Crear HMAC del mensaje (username + password + nonce)
            String message = username + password + nonce;
            String hmac = generateHMAC(message);

            // Enviar datos al servidor
            output.println(username);
            output.println(password);
            output.println(nonce);
            output.println(hmac);

            // Solicitar mensaje para enviar al servidor
            System.out.print("Introduce tu mensaje: ");
            String userMessage = scanner.nextLine();
            output.println(userMessage); // Enviar mensaje al servidor
            output.flush();

            // Leer respuesta del servidor
            String response = input.readLine();
            System.out.println("Respuesta del servidor: " + response);

            // Cerrar flujos y socket
            output.close();
            input.close();
            socket.close();
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para generar un nonce de 32 caracteres hexadecimales
    private static String generateNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonceBytes = new byte[16]; // 16 bytes * 2 = 32 caracteres hexadecimales
        secureRandom.nextBytes(nonceBytes);
        StringBuilder nonce = new StringBuilder();
        for (byte b : nonceBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) nonce.append('0');
            nonce.append(hex);
        }
        return nonce.toString();
    }

    // Método para generar HMAC usando HmacSHA256
    private static String generateHMAC(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(HMAC_KEY.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
