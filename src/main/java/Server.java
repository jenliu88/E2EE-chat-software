import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

public class Server {

    private static final int PORT = 12345;
    static List<ClientHandler> clients = Collections.synchronizedList(new ArrayList<>());
    static List<String> chatHistory = Collections.synchronizedList(new ArrayList<>());
    private static final String CHAT_LOG_FILE = "chatlog.txt";

    public static void main(String[] args) {
        loadChatHistory();

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server listening on port " + PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New client connected.");

                ClientHandler handler = new ClientHandler(socket);
                clients.add(handler);
                new Thread(handler).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Save message to memory and log file
    public static void addMessage(String message) {
        synchronized (chatHistory) {
            chatHistory.add(message);
            saveMessageToFile(message);
        }
    }

    // Broadcast a message to all clients
    public static void broadcast(String message, ClientHandler exclude) {
        synchronized (clients) {
            for (ClientHandler client : clients) {
                if (client != exclude) {
                    client.sendMessage(message);
                }
            }
        }
    }

    // Load messages from chatlog.txt on startup
    private static void loadChatHistory() {
        File file = new File(CHAT_LOG_FILE);
        if (!file.exists()) return;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                chatHistory.add(line);
            }
            System.out.println("Loaded chat history: " + chatHistory.size() + " messages.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Save a single message to chatlog.txt
    private static void saveMessageToFile(String message) {
        try (FileWriter fw = new FileWriter(CHAT_LOG_FILE, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
