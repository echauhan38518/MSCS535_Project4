
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;


public class TLSLocalTest {
    public static void main(String[] args) throws Exception {
        // Load keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        char[] password = "StrongPass#123".toCharArray();

        try (FileInputStream fis = new FileInputStream("serverkeystore.jks")) {
            ks.load(fis, password);
        }

        // Initialize key manager (for server identity)
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, password);

        // Initialize trust manager (for client trust)
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        // Build TLS context
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        try (SSLServerSocket server = (SSLServerSocket) ssf.createServerSocket(8443)) {
            System.out.println("Secure server running on port 8443...");

            // Accept one client connection
            new Thread(() -> {
                try {
                    Thread.sleep(500); // give server time to start
                    connectClient();   // start client
                } catch (Exception e) { e.printStackTrace(); }
            }).start();

            try (SSLSocket socket = (SSLSocket) server.accept()) {
                System.out.println("Client connected securely!");

                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                out.println("Hello from secure server!");
                System.out.println("Received from client: " + in.readLine());
            }
        }
    }

    static void connectClient() throws Exception {
        char[] password = "StrongPass#123".toCharArray();
        KeyStore ts = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream("serverkeystore.jks")) {
            ts.load(fis, password);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);

        SSLSocketFactory factory = ctx.getSocketFactory();
        try (SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 8443)) {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            System.out.println("Client received: " + in.readLine());
            out.println("Hello secure server, from client!");
        }
    }
}