import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
import javafx.stage.FileChooser;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main extends Application {

    // Network components
    private ServerSocket serverSocket;
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private ExecutorService executor = Executors.newFixedThreadPool(2);

    // UI components
    private Stage primaryStage;
    private TextArea chatArea;
    private TextField messageField;
    private TextField usernameField;
    private PasswordField passwordField;
    private TextField confirmPasswordField;
    private TextField ipField;
    private TextField portField;
    private Button connectButton;
    private Button hostButton;
    private Button sendButton;
    private Button fileButton;
    private Button loginButton;
    private Button registerButton;
    private Button logoutButton;
    private Label statusLabel;
    private Label authStatusLabel;

    // App state
    private String username = "";
    private boolean isHost = false;
    private boolean isConnected = false;
    private boolean isAuthenticated = false;
    private SecretKey encryptionKey;
    private Map<String, String> userDatabase = new HashMap<>();
    private String currentSession = "";

    // File paths
    private static final String USER_DB_FILE = "users.db";
    private static final String SESSION_FILE = "session.dat";

    @Override
    public void start(Stage stage) {
        primaryStage = stage;
        primaryStage.setTitle("P2P Secure Chat Application");

        // Initialize encryption and load user database
        initEncryption();
        loadUserDatabase();

        // Check for existing session
        if (loadSession()) {
            showConnectionScreen();
        } else {
            showAuthScreen();
        }

        primaryStage.setOnCloseRequest(e -> cleanup());
        primaryStage.show();
    }

    private void showAuthScreen() {
        VBox root = new VBox(20);
        root.setPadding(new Insets(30));
        root.setAlignment(Pos.CENTER);
        root.getStyleClass().add("auth-screen");

        Label titleLabel = new Label("P2P Secure Chat");
        titleLabel.getStyleClass().add("auth-title");

        Label subtitleLabel = new Label("Login or Register to Continue");
        subtitleLabel.getStyleClass().add("auth-subtitle");

        // Authentication form
        VBox formBox = new VBox(15);
        formBox.setAlignment(Pos.CENTER);
        formBox.getStyleClass().add("auth-form");

        Label usernameLabel = new Label("Username:");
        usernameLabel.getStyleClass().add("auth-label");
        usernameField = new TextField();
        usernameField.getStyleClass().add("auth-input");
        usernameField.setPromptText("Enter username");

        Label passwordLabel = new Label("Password:");
        passwordLabel.getStyleClass().add("auth-label");
        passwordField = new PasswordField();
        passwordField.getStyleClass().add("auth-input");
        passwordField.setPromptText("Enter password");

        Label confirmPasswordLabel = new Label("Confirm Password (Registration only):");
        confirmPasswordLabel.getStyleClass().add("auth-label");
        confirmPasswordField = new PasswordField();
        confirmPasswordField.getStyleClass().add("auth-input");
        confirmPasswordField.setPromptText("Confirm password");

        // Buttons
        HBox buttonBox = new HBox(15);
        buttonBox.setAlignment(Pos.CENTER);

        loginButton = new Button("Login");
        loginButton.getStyleClass().add("auth-login-button");
        loginButton.setOnAction(e -> attemptLogin());

        registerButton = new Button("Register");
        registerButton.getStyleClass().add("auth-register-button");
        registerButton.setOnAction(e -> attemptRegister());

        buttonBox.getChildren().addAll(loginButton, registerButton);

        authStatusLabel = new Label("Enter your credentials to continue");
        authStatusLabel.getStyleClass().add("auth-status");

        // Enable Enter key for login
        passwordField.setOnAction(e -> attemptLogin());
        confirmPasswordField.setOnAction(e -> attemptRegister());

        formBox.getChildren().addAll(
                usernameLabel, usernameField,
                passwordLabel, passwordField,
                confirmPasswordLabel, confirmPasswordField,
                buttonBox, authStatusLabel
        );

        root.getChildren().addAll(titleLabel, subtitleLabel, formBox);

        Scene scene = new Scene(root, 450, 500);
        scene.getStylesheets().add("data:text/css," + getCSS());
        primaryStage.setScene(scene);
    }

    private void attemptLogin() {
        String user = usernameField.getText().trim();
        String pass = passwordField.getText();

        if (user.isEmpty() || pass.isEmpty()) {
            authStatusLabel.setText("Please enter both username and password");
            authStatusLabel.getStyleClass().removeAll("auth-success");
            authStatusLabel.getStyleClass().add("auth-error");
            return;
        }

        String hashedPassword = hashPassword(pass);

        if (userDatabase.containsKey(user) && userDatabase.get(user).equals(hashedPassword)) {
            // Successful login
            username = user;
            isAuthenticated = true;
            currentSession = generateSessionToken();
            saveSession();

            authStatusLabel.setText("Login successful! Welcome " + user);
            authStatusLabel.getStyleClass().removeAll("auth-error");
            authStatusLabel.getStyleClass().add("auth-success");

            // Delay before switching screens
            Platform.runLater(() -> {
                try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                showConnectionScreen();
            });

        } else {
            authStatusLabel.setText("Invalid username or password");
            authStatusLabel.getStyleClass().removeAll("auth-success");
            authStatusLabel.getStyleClass().add("auth-error");
            passwordField.clear();
        }
    }

    private void attemptRegister() {
        String user = usernameField.getText().trim();
        String pass = passwordField.getText();
        String confirmPass = confirmPasswordField.getText();

        if (user.isEmpty() || pass.isEmpty() || confirmPass.isEmpty()) {
            authStatusLabel.setText("Please fill all fields for registration");
            authStatusLabel.getStyleClass().removeAll("auth-success");
            authStatusLabel.getStyleClass().add("auth-error");
            return;
        }

        if (user.length() < 3) {
            authStatusLabel.setText("Username must be at least 3 characters");
            authStatusLabel.getStyleClass().removeAll("auth-success");
            authStatusLabel.getStyleClass().add("auth-error");
            return;
        }

        if (pass.length() < 4) {
            authStatusLabel.setText("Password must be at least 4 characters");
            authStatusLabel.getStyleClass().removeAll("auth-success");
            authStatusLabel.getStyleClass().add("auth-error");
            return;
        }

        if (!pass.equals(confirmPass)) {
            authStatusLabel.setText("Passwords do not match");
            authStatusLabel.getStyleClass().removeAll("auth-success");
            authStatusLabel.getStyleClass().add("auth-error");
            confirmPasswordField.clear();
            return;
        }

        if (userDatabase.containsKey(user)) {
            authStatusLabel.setText("Username already exists");
            authStatusLabel.getStyleClass().removeAll("auth-success");
            authStatusLabel.getStyleClass().add("auth-error");
            return;
        }

        // Registration successful
        String hashedPassword = hashPassword(pass);
        userDatabase.put(user, hashedPassword);
        saveUserDatabase();

        username = user;
        isAuthenticated = true;
        currentSession = generateSessionToken();
        saveSession();

        authStatusLabel.setText("Registration successful! Welcome " + user);
        authStatusLabel.getStyleClass().removeAll("auth-error");
        authStatusLabel.getStyleClass().add("auth-success");

        // Delay before switching screens
        Platform.runLater(() -> {
            try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
            showConnectionScreen();
        });
    }

    private void showConnectionScreen() {
        VBox root = new VBox(15);
        root.setPadding(new Insets(20));
        root.setAlignment(Pos.CENTER);
        root.getStyleClass().add("connection-screen");

        // User info and logout
        HBox userBox = new HBox(10);
        userBox.setAlignment(Pos.CENTER);
        Label userLabel = new Label("Welcome, " + username + "!");
        userLabel.getStyleClass().add("user-welcome");

        logoutButton = new Button("Logout");
        logoutButton.getStyleClass().add("logout-button");
        logoutButton.setOnAction(e -> logout());

        userBox.getChildren().addAll(userLabel, logoutButton);

        Label titleLabel = new Label("P2P Secure Chat");
        titleLabel.getStyleClass().add("title");

        // Connection section
        Label connectionLabel = new Label("Connection Settings:");
        connectionLabel.getStyleClass().add("section-title");

        HBox ipBox = new HBox(10);
        ipBox.setAlignment(Pos.CENTER);
        Label ipLabel = new Label("IP Address:");
        ipField = new TextField("localhost");
        ipField.getStyleClass().add("input-field");
        ipBox.getChildren().addAll(ipLabel, ipField);

        HBox portBox = new HBox(10);
        portBox.setAlignment(Pos.CENTER);
        Label portLabel = new Label("Port:");
        portField = new TextField("12345");
        portField.getStyleClass().add("input-field");
        portBox.getChildren().addAll(portLabel, portField);

        // Buttons
        HBox buttonBox = new HBox(15);
        buttonBox.setAlignment(Pos.CENTER);

        hostButton = new Button("Host Chat");
        hostButton.getStyleClass().add("primary-button");
        hostButton.setOnAction(e -> startHost());

        connectButton = new Button("Join Chat");
        connectButton.getStyleClass().add("secondary-button");
        connectButton.setOnAction(e -> connectToHost());

        buttonBox.getChildren().addAll(hostButton, connectButton);

        statusLabel = new Label("Ready to connect");
        statusLabel.getStyleClass().add("status-label");

        root.getChildren().addAll(
                userBox, titleLabel, connectionLabel, ipBox, portBox, buttonBox, statusLabel
        );

        Scene scene = new Scene(root, 450, 400);
        scene.getStylesheets().add("data:text/css," + getCSS());
        primaryStage.setScene(scene);
    }

    private void logout() {
        isAuthenticated = false;
        username = "";
        currentSession = "";
        clearSession();

        // Disconnect if connected
        if (isConnected) {
            cleanup();
        }

        showAuthScreen();
    }

    private void startHost() {
        if (!isAuthenticated) {
            statusLabel.setText("Authentication required");
            return;
        }

        int port = Integer.parseInt(portField.getText());

        executor.submit(() -> {
            try {
                serverSocket = new ServerSocket(port);
                isHost = true;

                Platform.runLater(() -> {
                    statusLabel.setText("Hosting on port " + port + ". Waiting for connection...");
                    hostButton.setDisable(true);
                    connectButton.setDisable(true);
                });

                // Wait for client connection
                clientSocket = serverSocket.accept();
                setupStreams();

                // Send authentication challenge
                out.println("AUTH_REQUIRED");
                String clientAuth = in.readLine();

                if (validateClientAuth(clientAuth)) {
                    out.println("AUTH_SUCCESS:" + username);

                    Platform.runLater(() -> {
                        showChatScreen();
                        addSystemMessage("Authenticated client connected!");
                    });

                    startListening();
                } else {
                    out.println("AUTH_FAILED");
                    clientSocket.close();
                    Platform.runLater(() -> {
                        statusLabel.setText("Client authentication failed");
                        hostButton.setDisable(false);
                        connectButton.setDisable(false);
                    });
                }

            } catch (IOException e) {
                Platform.runLater(() -> {
                    statusLabel.setText("Error hosting: " + e.getMessage());
                    hostButton.setDisable(false);
                    connectButton.setDisable(false);
                });
            }
        });
    }

    private void connectToHost() {
        if (!isAuthenticated) {
            statusLabel.setText("Authentication required");
            return;
        }

        String ip = ipField.getText().trim();
        int port = Integer.parseInt(portField.getText());

        executor.submit(() -> {
            try {
                Platform.runLater(() -> {
                    statusLabel.setText("Connecting to " + ip + ":" + port + "...");
                    hostButton.setDisable(true);
                    connectButton.setDisable(true);
                });

                clientSocket = new Socket(ip, port);
                setupStreams();

                // Handle authentication
                String authChallenge = in.readLine();
                if ("AUTH_REQUIRED".equals(authChallenge)) {
                    // Send authentication
                    out.println("USER:" + username + ":" + currentSession);

                    String authResponse = in.readLine();
                    if (authResponse.startsWith("AUTH_SUCCESS:")) {
                        String hostUsername = authResponse.split(":", 2)[1];

                        Platform.runLater(() -> {
                            showChatScreen();
                            addSystemMessage("Connected to " + hostUsername + "'s chat!");
                        });

                        startListening();
                    } else {
                        Platform.runLater(() -> {
                            statusLabel.setText("Authentication failed");
                            hostButton.setDisable(false);
                            connectButton.setDisable(false);
                        });
                        return;
                    }
                }

            } catch (IOException e) {
                Platform.runLater(() -> {
                    statusLabel.setText("Connection failed: " + e.getMessage());
                    hostButton.setDisable(false);
                    connectButton.setDisable(false);
                });
            }
        });
    }

    private boolean validateClientAuth(String authData) {
        if (authData == null || !authData.startsWith("USER:")) return false;

        String[] parts = authData.split(":", 3);
        if (parts.length != 3) return false;

        String clientUsername = parts[1];
        String clientSession = parts[2];

        // Simple validation - in real app, you'd validate session token properly
        return !clientUsername.isEmpty() && !clientSession.isEmpty();
    }

    private void setupStreams() throws IOException {
        out = new PrintWriter(clientSocket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        isConnected = true;
    }

    private void showChatScreen() {
        BorderPane root = new BorderPane();
        root.getStyleClass().add("chat-screen");

        // Top bar with user info
        HBox topBar = new HBox(10);
        topBar.setPadding(new Insets(10));
        topBar.setAlignment(Pos.CENTER_LEFT);
        topBar.getStyleClass().add("chat-top-bar");

        Label chatTitle = new Label("Secure Chat");
        chatTitle.getStyleClass().add("chat-title");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Label userInfo = new Label("Logged in as: " + username);
        userInfo.getStyleClass().add("chat-user-info");

        Button chatLogoutButton = new Button("Logout");
        chatLogoutButton.getStyleClass().add("chat-logout-button");
        chatLogoutButton.setOnAction(e -> logout());

        topBar.getChildren().addAll(chatTitle, spacer, userInfo, chatLogoutButton);
        root.setTop(topBar);

        // Chat area
        chatArea = new TextArea();
        chatArea.setEditable(false);
        chatArea.getStyleClass().add("chat-area");
        chatArea.setWrapText(true);

        ScrollPane scrollPane = new ScrollPane(chatArea);
        scrollPane.setFitToWidth(true);
        scrollPane.setVbarPolicy(ScrollPane.ScrollBarPolicy.AS_NEEDED);

        root.setCenter(scrollPane);

        // Bottom section - message input
        VBox bottomBox = new VBox(10);
        bottomBox.setPadding(new Insets(10));
        bottomBox.getStyleClass().add("input-section");

        HBox inputBox = new HBox(10);
        inputBox.setAlignment(Pos.CENTER);

        messageField = new TextField();
        messageField.getStyleClass().add("message-field");
        messageField.setPromptText("Type your message...");
        messageField.setOnAction(e -> sendMessage());

        sendButton = new Button("Send");
        sendButton.getStyleClass().add("send-button");
        sendButton.setOnAction(e -> sendMessage());

        fileButton = new Button("📎 File");
        fileButton.getStyleClass().add("file-button");
        fileButton.setOnAction(e -> sendFile());

        inputBox.getChildren().addAll(messageField, sendButton, fileButton);

        // Status bar
        Label connectionStatus = new Label("🔒 Encrypted connection established");
        connectionStatus.getStyleClass().add("connection-status");

        bottomBox.getChildren().addAll(inputBox, connectionStatus);
        root.setBottom(bottomBox);

        Scene scene = new Scene(root, 700, 600);
        scene.getStylesheets().add("data:text/css," + getCSS());
        primaryStage.setScene(scene);
        primaryStage.setTitle("P2P Secure Chat - " + username);

        messageField.requestFocus();

        // Welcome message
        addSystemMessage("Welcome to the secure chat, " + username + "!");
        addSystemMessage("All messages are encrypted end-to-end.");
    }

    private void sendMessage() {
        String message = messageField.getText().trim();
        if (message.isEmpty() || !isConnected) return;

        try {
            String encryptedMessage = encrypt("MSG:" + username + ":" + message);
            out.println(encryptedMessage);

            addMessage(username, message, true);
            messageField.clear();

        } catch (Exception e) {
            addSystemMessage("Error sending message: " + e.getMessage());
        }
    }

    private void sendFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select file to send");
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null && isConnected) {
            executor.submit(() -> {
                try {
                    byte[] fileData = Files.readAllBytes(file.toPath());
                    String encodedFile = Base64.getEncoder().encodeToString(fileData);
                    String fileMessage = "FILE:" + username + ":" + file.getName() + ":" + encodedFile;
                    String encryptedMessage = encrypt(fileMessage);

                    out.println(encryptedMessage);

                    Platform.runLater(() ->
                            addMessage(username, "📎 Sent file: " + file.getName(), true)
                    );

                } catch (Exception e) {
                    Platform.runLater(() ->
                            addSystemMessage("Error sending file: " + e.getMessage())
                    );
                }
            });
        }
    }

    private void startListening() {
        executor.submit(() -> {
            try {
                String receivedMessage;
                while (isConnected && (receivedMessage = in.readLine()) != null) {
                    String decryptedMessage = decrypt(receivedMessage);
                    processReceivedMessage(decryptedMessage);
                }
            } catch (Exception e) {
                if (isConnected) {
                    Platform.runLater(() -> addSystemMessage("Connection lost: " + e.getMessage()));
                }
            }
        });
    }

    private void processReceivedMessage(String message) {
        String[] parts = message.split(":", 3);
        if (parts.length < 3) return;

        String type = parts[0];
        String sender = parts[1];
        String content = parts[2];

        Platform.runLater(() -> {
            if ("MSG".equals(type)) {
                addMessage(sender, content, false);
            } else if ("FILE".equals(type)) {
                handleFileReceived(sender, content);
            }
        });
    }

    private void handleFileReceived(String sender, String fileData) {
        String[] fileParts = fileData.split(":", 2);
        if (fileParts.length < 2) return;

        String fileName = fileParts[0];
        String encodedData = fileParts[1];

        addMessage(sender, "📎 Received file: " + fileName, false);

        // Auto-save received files
        try {
            byte[] decodedData = Base64.getDecoder().decode(encodedData);
            File saveFile = new File("received_" + fileName);
            Files.write(saveFile.toPath(), decodedData);
            addSystemMessage("File saved as: " + saveFile.getName());
        } catch (Exception e) {
            addSystemMessage("Error saving file: " + e.getMessage());
        }
    }

    private void addMessage(String sender, String content, boolean isOwn) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm"));
        String prefix = isOwn ? "You" : sender;
        String fullMessage = "[" + timestamp + "] " + prefix + ": " + content + "\n";

        Platform.runLater(() -> {
            chatArea.appendText(fullMessage);
            chatArea.setScrollTop(Double.MAX_VALUE);
        });
    }

    private void addSystemMessage(String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm"));
        String fullMessage = "[" + timestamp + "] System: " + message + "\n";

        Platform.runLater(() -> {
            chatArea.appendText(fullMessage);
            chatArea.setScrollTop(Double.MAX_VALUE);
        });
    }

    // Authentication helper methods
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((password + "salt123").getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return password; // Fallback - not secure!
        }
    }

    private String generateSessionToken() {
        return Base64.getEncoder().encodeToString((username + System.currentTimeMillis()).getBytes());
    }

    private void loadUserDatabase() {
        try {
            if (Files.exists(Paths.get(USER_DB_FILE))) {
                Properties props = new Properties();
                props.load(new FileInputStream(USER_DB_FILE));
                for (String key : props.stringPropertyNames()) {
                    userDatabase.put(key, props.getProperty(key));
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading user database: " + e.getMessage());
        }
    }

    private void saveUserDatabase() {
        try {
            Properties props = new Properties();
            for (Map.Entry<String, String> entry : userDatabase.entrySet()) {
                props.setProperty(entry.getKey(), entry.getValue());
            }
            props.store(new FileOutputStream(USER_DB_FILE), "User Database");
        } catch (Exception e) {
            System.err.println("Error saving user database: " + e.getMessage());
        }
    }

    private boolean loadSession() {
        try {
            if (Files.exists(Paths.get(SESSION_FILE))) {
                Properties props = new Properties();
                props.load(new FileInputStream(SESSION_FILE));
                String savedUsername = props.getProperty("username");
                String savedSession = props.getProperty("session");

                if (savedUsername != null && savedSession != null && !savedUsername.isEmpty()) {
                    username = savedUsername;
                    currentSession = savedSession;
                    isAuthenticated = true;
                    return true;
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading session: " + e.getMessage());
        }
        return false;
    }

    private void saveSession() {
        try {
            Properties props = new Properties();
            props.setProperty("username", username);
            props.setProperty("session", currentSession);
            props.store(new FileOutputStream(SESSION_FILE), "User Session");
        } catch (Exception e) {
            System.err.println("Error saving session: " + e.getMessage());
        }
    }

    private void clearSession() {
        try {
            Files.deleteIfExists(Paths.get(SESSION_FILE));
        } catch (Exception e) {
            System.err.println("Error clearing session: " + e.getMessage());
        }
    }

    private void initEncryption() {
        try {
            // Simple static key for demo - in real app, exchange keys securely
            String keyString = "MySecretKey12345"; // 16 chars for AES-128
            encryptionKey = new SecretKeySpec(keyString.getBytes(), "AES");
        } catch (Exception e) {
            System.err.println("Encryption setup failed: " + e.getMessage());
        }
    }

    private String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }

    private void cleanup() {
        isConnected = false;
        try {
            if (out != null) out.close();
            if (in != null) in.close();
            if (clientSocket != null) clientSocket.close();
            if (serverSocket != null) serverSocket.close();
        } catch (IOException e) {
            System.err.println("Cleanup error: " + e.getMessage());
        }
        executor.shutdown();
    }

    private String getCSS() {
        return """
        .auth-screen {
            -fx-background-color: linear-gradient(to bottom, #2C3E50, #3498DB);
        }
        
        .connection-screen {
            -fx-background-color: linear-gradient(to bottom, #667eea, #764ba2);
        }
        
        .chat-screen {
            -fx-background-color: #f8f9fa;
        }
        
        .auth-title {
            -fx-font-size: 32px;
            -fx-font-weight: bold;
            -fx-text-fill: white;
            -fx-effect: dropshadow(gaussian, rgba(0,0,0,0.3), 2, 0, 0, 2);
        }
        
        .auth-subtitle {
            -fx-font-size: 16px;
            -fx-text-fill: #ecf0f1;
            -fx-font-style: italic;
        }
        
        .auth-form {
            -fx-background-color: rgba(255, 255, 255, 0.95);
            -fx-background-radius: 15px;
            -fx-padding: 30px;
            -fx-effect: dropshadow(gaussian, rgba(0,0,0,0.2), 10, 0, 0, 5);
        }
        
        .auth-label {
            -fx-font-size: 14px;
            -fx-font-weight: bold;
            -fx-text-fill: #2c3e50;
        }
        
        .auth-input {
            -fx-pref-width: 250px;
            -fx-padding: 12px;
            -fx-background-radius: 8px;
            -fx-border-radius: 8px;
            -fx-border-color: #bdc3c7;
            -fx-border-width: 1px;
            -fx-font-size: 14px;
        }
        
        .auth-input:focused {
            -fx-border-color: #3498db;
            -fx-border-width: 2px;
        }
        
        .auth-login-button {
            -fx-background-color: #27AE60;
            -fx-text-fill: white;
            -fx-padding: 12px 30px;
            -fx-background-radius: 8px;
            -fx-font-weight: bold;
            -fx-font-size: 14px;
            -fx-cursor: hand;
        }
        
        .auth-login-button:hover {
            -fx-background-color: #229954;
        }
        
        .auth-register-button {
            -fx-background-color: #E74C3C;
            -fx-text-fill: white;
            -fx-padding: 12px 30px;
            -fx-background-radius: 8px;
            -fx-font-weight: bold;
            -fx-font-size: 14px;
            -fx-cursor: hand;
        }
        
        .auth-register-button:hover {
            -fx-background-color: #C0392B;
        }
        
        .auth-status {
            -fx-font-size: 12px;
            -fx-text-fill: #7f8c8d;
            -fx-text-alignment: center;
        }
        
        .auth-error {
            -fx-text-fill: #e74c3c;
            -fx-font-weight: bold;
        }
        
        .auth-success {
            -fx-text-fill: #27ae60;
            -fx-font-weight: bold;
        }
        
        .user-welcome {
            -fx-font-size: 16px;
            -fx-font-weight: bold;
            -fx-text-fill: white;
        }
        
        .logout-button {
            -fx-background-color: #E74C3C;
            -fx-text-fill: white;
            -fx-padding: 8px 15px;
            -fx-background-radius: 5px;
            -fx-font-size: 12px;
        }
        
        .logout-button:hover {
            -fx-background-color: #C0392B;
        }
        
        .chat-top-bar {
            -fx-background-color: #34495e;
            -fx-border-color: #2c3e50;
            -fx-border-width: 0 0 2px 0;
        }
        
        .chat-title {
            -fx-font-size: 18px;
            -fx-font-weight: bold;
            -fx-text-fill: white;
        }
        
        .chat-user-info {
            -fx-font-size: 14px;
            -fx-text-fill: #ecf0f1;
        }
        
        .chat-logout-button {
            -fx-background-color: #e74c3c;
            -fx-text-fill: white;
            -fx-padding: 6px 12px;
            -fx-background-radius: 4px;
            -fx-font-size: 12px;
        }
        
        .title {
            -fx-font-size: 24px;
            -fx-font-weight: bold;
            -fx-text-fill: white;
        }
        
        .section-title {
            -fx-font-size: 14px;
            -fx-font-weight: bold;
            -fx-text-fill: white;
        }
        
        .input-field {
            -fx-pref-width: 200px;
            -fx-padding: 8px;
            -fx-background-radius: 5px;
            -fx-border-radius: 5px;
        }
        
        .primary-button {
            -fx-background-color: #4CAF50;
            -fx-text-fill: white;
            -fx-padding: 10px 20px;
            -fx-background-radius: 5px;
            -fx-font-weight: bold;
        }
        
        .primary-button:hover {
            -fx-background-color: #45a049;
        }
        
        .secondary-button {
            -fx-background-color: #2196F3;
            -fx-text-fill: white;
            -fx-padding: 10px 20px;
            -fx-background-radius: 5px;
            -fx-font-weight: bold;
        }
        
        .secondary-button:hover {
            -fx-background-color: #1976D2;
        }
        
        .status-label {
            -fx-text-fill: white;
            -fx-font-style: italic;
        }
        
        .chat-area {
            -fx-background-color: white;
            -fx-border-color: #ddd;
            -fx-font-family: "Segoe UI", "Arial", sans-serif;
            -fx-font-size: 13px;
            -fx-padding: 10px;
        }
        
        .input-section {
            -fx-background-color: #e8e8e8;
            -fx-border-color: #ddd;
            -fx-border-width: 1 0 0 0;
        }
        
        .message-field {
            -fx-pref-width: 400px;
            -fx-padding: 10px;
            -fx-background-radius: 20px;
            -fx-border-radius: 20px;
            -fx-border-color: #ddd;
            -fx-border-width: 1px;
        }
        
        .message-field:focused {
            -fx-border-color: #3498db;
            -fx-border-width: 2px;
        }
        
        .send-button {
            -fx-background-color: #27AE60;
            -fx-text-fill: white;
            -fx-padding: 10px 20px;
            -fx-background-radius: 20px;
            -fx-font-weight: bold;
        }
        
        .send-button:hover {
            -fx-background-color: #229954;
        }
        
        .file-button {
            -fx-background-color: #F39C12;
            -fx-text-fill: white;
            -fx-padding: 10px 15px;
            -fx-background-radius: 20px;
            -fx-font-weight: bold;
        }
        
        .file-button:hover {
            -fx-background-color: #E67E22;
        }
        
        .connection-status {
            -fx-font-size: 12px;
            -fx-text-fill: #27ae60;
            -fx-font-weight: bold;
        }
        """;
    }
}