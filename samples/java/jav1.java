package samples.java;

import java.awt.*;
import java.io.*;
import java.util.Base64;
import javax.swing.*;

public class jav1 extends JFrame {
    
    private JTextField cmdField, userField, nameField, dataField;
    private JTextArea outputArea;
    
    public jav1() {
        super("Java Security Vulnerabilities Demo");
        setupUI();
    }
    
    private void setupUI() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(700, 500);
        setLayout(new BorderLayout());
        
        // Input panel
        JPanel inputPanel = new JPanel(new GridLayout(5, 2, 5, 5));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 1. Command injection vulnerability
        inputPanel.add(new JLabel("Command (try 'calc' or 'echo hello'):"));
        cmdField = new JTextField();
        inputPanel.add(cmdField);
        
        // 2. SQL injection vulnerability
        inputPanel.add(new JLabel("Username (try 'admin' OR '1'='1'):"));
        userField = new JTextField();
        inputPanel.add(userField);
        
        // 3. XSS vulnerability
        inputPanel.add(new JLabel("Name (try <script>alert('test')</script>):"));
        nameField = new JTextField();
        inputPanel.add(nameField);
        
        // 4. Insecure deserialization
        inputPanel.add(new JLabel("Serialized Data:"));
        dataField = new JTextField();
        inputPanel.add(dataField);
        
        // Execute button
        JButton executeBtn = new JButton("Execute Vulnerable Code");
        executeBtn.addActionListener(e -> executeVulnerabilities());
        inputPanel.add(executeBtn);
        
        add(inputPanel, BorderLayout.NORTH);
        
        // Output area
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setBackground(new Color(255, 250, 240));
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        add(new JScrollPane(outputArea), BorderLayout.CENTER);
        
        // Info panel
        JLabel warningLabel = new JLabel("⚠️ WARNING: This demonstrates security vulnerabilities - do not use in production!");
        warningLabel.setForeground(Color.RED);
        warningLabel.setHorizontalAlignment(SwingConstants.CENTER);
        add(warningLabel, BorderLayout.SOUTH);
        
        setVisible(true);
    }
    
    @SuppressWarnings("UseSpecificCatch")
    private void executeVulnerabilities() {
        outputArea.setText("");
        outputArea.setForeground(Color.BLACK);
        
        // 1. Command injection (Runtime.exec with user input)
        String cmd = cmdField.getText();
        if (!cmd.isEmpty()) {
            outputArea.append("1. COMMAND INJECTION VULNERABILITY:\n");
            outputArea.append("Executing command: " + cmd + "\n");
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    outputArea.append("Output: " + line + "\n");
                }
            } catch (IOException ex) {
                outputArea.append("Error: " + ex.getMessage() + "\n");
            }
            outputArea.append("----------------------------------------\n");
        }
        
        // 2. SQL injection (concatenating user input into query)
        String user = userField.getText();
        if (!user.isEmpty()) {
            outputArea.append("2. SQL INJECTION VULNERABILITY:\n");
            outputArea.append("Querying user: " + user + "\n");
            String sql = "SELECT * FROM users WHERE username = '" + user + "'";
            outputArea.append("Generated SQL: " + sql + "\n");
            outputArea.append("This would return all users if input was: admin' OR '1'='1\n");
            outputArea.append("----------------------------------------\n");
        }
        
        // 3. XSS (reflecting user input without sanitization)
        String name = nameField.getText();
        if (!name.isEmpty()) {
            outputArea.append("3. XSS VULNERABILITY:\n");
            outputArea.append("Rendering user input without sanitization:\n");
            outputArea.append("<div>Hello, " + name + "!</div>\n");
            outputArea.append("In a web browser, script tags would execute!\n");
            outputArea.append("----------------------------------------\n");
        }
        
        // 4. Insecure deserialization
        String data = dataField.getText();
        if (!data.isEmpty()) {
            outputArea.append("4. INSECURE DESERIALIZATION VULNERABILITY:\n");
            outputArea.append("Deserializing data: " + data + "\n");
            try {
                byte[] decodedData = Base64.getDecoder().decode(data);
                ByteArrayInputStream bais = new ByteArrayInputStream(decodedData);
                ObjectInputStream ois = new ObjectInputStream(bais);
                Object obj = ois.readObject();
                outputArea.append("Deserialized object: " + obj.toString() + "\n");
            } catch (Exception ex) {
                outputArea.append("Error: " + ex.getMessage() + "\n");
            }
            outputArea.append("----------------------------------------\n");
        }
        
        if (cmd.isEmpty() && user.isEmpty() && name.isEmpty() && data.isEmpty()) {
            outputArea.append("Please enter data in at least one field to test vulnerabilities.\n");
        } else {
            outputArea.append("ALL VULNERABILITIES EXECUTED SUCCESSFULLY!\n");
            outputArea.append("These are examples of what NOT to do in production code.\n");
        }
    }
    
    @SuppressWarnings({"UseSpecificCatch", "CallToPrintStackTrace"})
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        SwingUtilities.invokeLater(() -> {
            new jav1();
        });
    }
    
    // Simple serializable class for demonstration
    @SuppressWarnings("unused")
    static class TestData implements Serializable {
        private final String data;
        
        public TestData(String data) {
            this.data = data;
        }
        
        @Override
        public String toString() {
            return "TestData: " + data;
        }
    }
}