import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set; // Para almacenar nonces usados
import java.sql.Connection; // Para la conexión a la base de datos
import java.sql.DriverManager; // Para el manejo de la conexión
import java.sql.PreparedStatement; // Para preparar consultas SQL
import java.sql.ResultSet; // Para manejar resultados de consultas
import javax.crypto.Mac; // Para HMAC
import javax.crypto.spec.SecretKeySpec; // Para crear la clave HMAC

public class servidor {

    private static final String DB_URL = "jdbc:sqlite:usuarios.db"; // URL de la base de datos
    private static final Set<String> usedNonces = new HashSet<>(); // Set para almacenar nonces usados
    private static final String HMAC_KEY = "clave_secreta"; // Clave secreta para HMAC

    public static void main(String[] args) {
        try {
			System.setProperty("https.protocols", "TLSv1.3");
            System.setProperty("javax.net.ssl.keyStore", "keystore.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "PasswordST3");

            SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(3343);
			

            System.out.println("Servidor SSL esperando conexiones...");

            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
				System.out.println("Protocolo utilizado: " + socket.getSession().getProtocol());

                System.out.println("Cliente conectado...");

                // Crear flujos de entrada y salida
                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

                // Leer usuario, contraseña, nonce y HMAC del cliente
                String usuario = input.readLine().trim();
                String contrasena = input.readLine().trim();
                String nonce = input.readLine().trim();
                String hmac = input.readLine().trim();
                String userMessage = input.readLine().trim(); // Leer el mensaje del cliente

                // Imprimir el nonce y el HMAC recibido
                System.out.println("Nonce recibido: " + nonce);
                System.out.println("HMAC recibido: " + hmac);

                // Verificar si el nonce ya ha sido usado
                if (usedNonces.contains(nonce)) {
                    System.out.println("ALERTA INTRUSO: ATAQUE REPLAY detectado. Nonce ya utilizado.");
                    output.println("Nonce ya utilizado. Mensaje no almacenado.");
                    output.flush();
                    socket.close();
                    continue;
                }

                // Verificar HMAC
                String message = usuario + contrasena + nonce;
                String computedHmac = generateHMAC(message); // HMAC calculado
                if (!verifyHMAC(message, hmac)) {
                    System.out.println("ALERTA INTRUSO: ATAQUE MAN IN THE MIDDLE detectado. HMAC no coincide.");
                    System.out.println("HMAC calculado: " + computedHmac);
                    output.println("HMAC inválido. Mensaje no almacenado.");
                    output.flush();
                    socket.close();
                    continue;
                }

                // Imprimir el mensaje recibido del cliente
                System.out.println("Mensaje recibido del cliente: " + userMessage);

                // Verificar credenciales desde la base de datos
                if (verificarCredenciales(usuario, contrasena)) {
                    usedNonces.add(nonce); // Almacenar el nonce usado
                    output.println("Mensaje SECRETO almacenado correctamente.");
                } else {
                    output.println("Usuario o contraseña incorrectos. Mensaje no almacenado.");
                }

                output.flush();
                output.close();
                input.close();
                socket.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para verificar credenciales en la base de datos
    private static boolean verificarCredenciales(String usuario, String contrasena) {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            String sql = "SELECT contrasena FROM usuarios WHERE usuario = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, usuario);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        String storedHash = rs.getString("contrasena");
                        // Comparar el hash almacenado con el hash de la contraseña introducida
                        String inputHash = hashPassword(contrasena);
                        return storedHash.equals(inputHash);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false; // Usuario no encontrado o error
    }

    // Método para hashear la contraseña utilizando SHA-256
    private static String hashPassword(String contrasena) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(contrasena.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Método para verificar HMAC
    private static boolean verifyHMAC(String data, String hmac) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(HMAC_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String computedHmac = Base64.getEncoder().encodeToString(hmacBytes);
            return computedHmac.equals(hmac);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    // Método para generar HMAC usando HmacSHA256
    private static String generateHMAC(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(HMAC_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
