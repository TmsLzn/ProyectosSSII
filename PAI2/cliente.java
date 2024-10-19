import javax.net.ssl.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class cliente {

    private static final String HMAC_KEY = "clave_secreta"; // Debe coincidir con el del servidor

    public static void main(String[] args) {
        try {
            String username, password, userMessage;

            // Si no se proporcionan argumentos, pedir los datos manualmente
            if (args.length < 3) {
                Scanner scanner = new Scanner(System.in);
                System.out.print("Introduce tu username: ");
                username = scanner.nextLine();
                System.out.print("Introduce tu contraseña: ");
                password = scanner.nextLine();
                System.out.print("Introduce tu mensaje: ");
                userMessage = scanner.nextLine();
                scanner.close();
            } else {
                // Obtener username, password y mensaje de los argumentos
                username = args[0];
                password = args[1];
                userMessage = args[2];
            }

            // Crear conexión SSL
            SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 3343);

            // Crear flujos de entrada y salida
            PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

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
            output.println(userMessage); // Enviar mensaje al servidor
            output.flush();

            // Leer respuesta del servidor
            String response = input.readLine();
            System.out.println("Respuesta del servidor: " + response);

            // Cerrar flujos y socket
            output.close();
            input.close();
            socket.close();

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
