<?php
// -------------------------------
// Intentionally Vulnerable PHP File (30 Vulns)
// -------------------------------

// 1. Hardcoded credentials
$admin_user = "admin";
$admin_pass = "12345";

// 2. Displaying PHP errors publicly
ini_set('display_errors', 1);

// 3. Using deprecated mysql_* (instead of PDO/MySQLi)
$conn = mysql_connect("localhost", "root", "root");
mysql_select_db("testdb", $conn);

// 4. No input validation (SQL Injection possible)
if (isset($_GET['id'])) {
    $id = $_GET['id']; 
    $res = mysql_query("SELECT * FROM users WHERE id=$id"); // vuln: SQLi
    while ($row = mysql_fetch_assoc($res)) {
        echo "User: " . $row['username'] . "<br>";
    }
}

// 5. Command injection
if (isset($_GET['ping'])) {
    system("ping -c 1 " . $_GET['ping']); 
}

// 6. File inclusion
if (isset($_GET['page'])) {
    include($_GET['page'] . ".php"); 
}

// 7. Insecure file upload (no validation)
if (isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);
}

// 8. Path traversal
if (isset($_GET['read'])) {
    $file = $_GET['read'];
    echo file_get_contents("uploads/" . $file);
}

// 9. XSS
if (isset($_GET['msg'])) {
    echo "Message: " . $_GET['msg']; 
}

// 10. Session fixation
session_start();
if (isset($_GET['sid'])) {
    session_id($_GET['sid']); 
}

// 11. Weak session management
$_SESSION['user'] = $_GET['user'] ?? "guest";

// 12. Insecure eval
if (isset($_GET['code'])) {
    eval($_GET['code']); 
}

// 13. Unserialized input
if (isset($_POST['data'])) {
    $obj = unserialize($_POST['data']); 
}

// 14. CSRF (no token check)
if (isset($_POST['updateEmail'])) {
    mysql_query("UPDATE users SET email='{$_POST['email']}' WHERE id=1"); 
}

// 15. Open redirect
if (isset($_GET['url'])) {
    header("Location: " . $_GET['url']); 
}

// 16. Using GET for login (leaks creds in URL)
if (isset($_GET['login'])) {
    if ($_GET['user'] == $admin_user && $_GET['pass'] == $admin_pass) {
        echo "Welcome Admin";
    }
}

// 17. No password hashing
if (isset($_POST['register'])) {
    $u = $_POST['user']; 
    $p = $_POST['pass']; 
    mysql_query("INSERT INTO users (username, password) VALUES ('$u','$p')");
}

// 18. No rate limiting (brute force possible)
if (isset($_POST['brute'])) {
    echo "Password check for " . $_POST['brute'];
}

// 19. Insecure cookie storage
setcookie("auth", $_GET['auth'] ?? "none");

// 20. Information disclosure
phpinfo();

// 21. Insecure deserialization with objects
class Test { public $cmd; function __wakeup(){ system($this->cmd); } }

// 22. Hardcoded API key
$apiKey = "SECRET-API-KEY-123";

// 23. Insecure random generator
$token = rand();

// 24. No SSL check
$ctx = stream_context_create(["ssl"=>["verify_peer"=>false]]);
file_get_contents("https://untrusted-site.com/data", false, $ctx);

// 25. Exposing server path
echo __FILE__;

// 26. Log injection
if (isset($_GET['log'])) {
    file_put_contents("log.txt", $_GET['log'], FILE_APPEND);
}

// 27. HTTP Response splitting
if (isset($_GET['header'])) {
    header("X-Test: " . $_GET['header']);
}

// 28. Race condition (no lock)
if (isset($_GET['balance'])) {
    $b = file_get_contents("balance.txt");
    $b++;
    file_put_contents("balance.txt", $b);
}

// 29. Use of md5 for password storage
if (isset($_POST['pwd'])) {
    $hash = md5($_POST['pwd']); 
    echo "MD5 Hash: $hash";
}

// 30. No output escaping in HTML attributes
if (isset($_GET['attr'])) {
    echo "<input value='" . $_GET['attr'] . "'>";
}
?>
