public class SimuladorClientes {
    public static void main(String[] args) {
        String[] usuarios = {"admin", "robledo", "kenzo"};
        String[] contrasenas = {"password123", "robledo", "kenzo"};

        for (int i = 0; i < 300; i++) {
            final int clientId = i; // Crear un ID único para cada cliente
            new Thread(() -> {
                try {
                    // Usar uno de los 3 usuarios disponibles
                    String username = usuarios[clientId % 3];  // Distribuir entre los 3 usuarios
                    String password = contrasenas[clientId % 3];  // Usar las contraseñas correspondientes
                    String message = "Mensaje del cliente " + clientId;

                    cliente.main(new String[]{username, password, message}); // Llamar al cliente con datos automáticos
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
}
