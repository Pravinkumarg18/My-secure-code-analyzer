<?php
/**
 * ADDITIONAL VULNERABLE PHP CODE EXAMPLES - FOR SECURITY TESTING ONLY
 * This file contains 20 additional security vulnerabilities for testing purposes.
 * DO NOT USE IN PRODUCTION!
 */

// 1. Open Redirect without Validation
function openRedirect() {
    $redirect = $_GET['redirect'];
    // No validation of redirect URL
    header("Location: " . $redirect);
    exit;
}

// 2. LDAP Injection
function ldapInjection() {
    $username = $_GET['username'];
    $password = $_GET['password'];
    
    $ldapconn = ldap_connect("ldap.example.com");
    $ldapbind = ldap_bind($ldapconn, "cn=root,dc=example,dc=com", "password");
    
    // LDAP injection vulnerability
    $filter = "(uid=" . $username . ")";
    $result = ldap_search($ldapconn, "dc=example,dc=com", $filter);
}

// 3. XPath Injection
function xpathInjection() {
    $name = $_GET['name'];
    
    $xml = simplexml_load_file('users.xml');
    // XPath injection vulnerability
    $result = $xml->xpath("//user[name='" . $name . "']");
    
    return $result;
}

// 4. HTTP Response Splitting
function httpResponseSplitting() {
    $filename = $_GET['file'];
    // HTTP response splitting vulnerability
    header("Content-Disposition: attachment; filename=" . $filename);
    readfile("uploads/" . $filename);
}

// 5. Timing Attack (String Comparison)
function timingAttack() {
    $password = $_POST['password'];
    $stored_hash = "5f4dcc3b5aa765d61d8327deb882cf99"; // md5 of "password"
    
    // Vulnerable to timing attack
    if (md5($password) === $stored_hash) {
        return true;
    }
    return false;
}

// 6. Insecure Cookie Handling
function insecureCookies() {
    // Session cookie without secure and httponly flags
    session_set_cookie_params(0, '/', '', false, false);
    session_start();
    
    // Setting sensitive data in cookies without encryption
    setcookie("user_data", base64_encode(serialize($_SESSION)), time()+3600, "/", "", false, false);
}

// 7. Unsafe use of globals
function unsafeGlobals() {
    // Registering globals (deprecated but still a vulnerability if enabled)
    if (!ini_get('register_globals')) {
        foreach ($_REQUEST as $key => $value) {
            $$key = $value; // Creates variables from request parameters
        }
    }
    
    echo "Welcome, $username"; // $username comes directly from request
}

// 8. Reflection Injection
function reflectionInjection() {
    $class = $_GET['class'];
    $method = $_GET['method'];
    
    // Reflection injection vulnerability
    $reflectionClass = new ReflectionClass($class);
    $instance = $reflectionClass->newInstance();
    
    $reflectionMethod = new ReflectionMethod($class, $method);
    return $reflectionMethod->invoke($instance);
}

// 9. Unsafe Regular Expression (ReDoS)
function redosVulnerability() {
    $input = $_GET['input'];
    
    // Vulnerable regex pattern (exponential backtracking)
    $pattern = '/(a+)+$/';
    
    if (preg_match($pattern, $input)) {
        return "Match found";
    }
    return "No match";
}

// 10. Type Juggling Vulnerability
function typeJuggling() {
    $password = $_POST['password'];
    $stored_hash = "0e12345"; // Example hash that evaluates to 0 in scientific notation
    
    // Type juggling vulnerability (== instead of ===)
    if (md5($password) == $stored_hash) {
        return true;
    }
    return false;
}

// 11. Unsafe use of exec() with user input
function execInjection() {
    $command = $_GET['command'];
    
    // Unsafe execution of user input
    exec("ls -la " . $command, $output);
    
    return $output;
}

// 12. XML Entity Expansion (Billion Laughs Attack)
function billionLaughs() {
    $xml = $_POST['xml'];
    
    // Vulnerable to Billion Laughs attack
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);
    
    return $doc->saveXML();
}

// 13. Unsafe use of preg_replace with /e modifier
function pregReplaceEval() {
    $template = $_GET['template'];
    $data = array('name' => $_GET['name']);
    
    // Dangerous preg_replace with /e modifier (deprecated in PHP 5.5, removed in 7.0)
    $result = preg_replace('/\{(\w+)\}/e', '$data["$1"]', $template);
    
    return $result;
}

// 14. Unsafe use of assert()
function assertInjection() {
    $code = $_GET['code'];
    
    // assert() evaluates PHP code - dangerous with user input
    assert($code);
}

// 15. Insecure Randomness for Security Purpose
function insecureRandom() {
    // Using insecure random function for cryptographic purpose
    $token = mt_rand(); // Not cryptographically secure
    
    // Using rand() for password reset token
    $reset_token = rand(100000, 999999);
    
    return array('token' => $token, 'reset_token' => $reset_token);
}

// 16. Unsafe use of extract() with EXTR_SKIP
function extractSkipVulnerability() {
    // EXTR_SKIP doesn't protect against existing variables
    extract($_GET, EXTR_SKIP);
    
    echo "Welcome, $username";
}

// 17. Directory Listing Enabled
function directoryListing() {
    $dir = $_GET['dir'];
    
    // Display directory contents without authentication
    $files = scandir($dir);
    
    foreach ($files as $file) {
        echo "<a href='$dir/$file'>$file</a><br>";
    }
}

// 18. Unsafe use of ${} variable variables
function variableVariableInjection() {
    $var = $_GET['var'];
    $value = $_GET['value'];
    
    // Unsafe variable variable usage
    ${$var} = $value;
    
    echo "Variable $$var set to: " . ${$var};
}

// 19. Password in URL (GET parameter)
function passwordInUrl() {
    $username = $_GET['username'];
    $password = $_GET['password']; // Password in URL - visible in logs
    
    // Authentication logic
    if (authenticateUser($username, $password)) {
        return "Login successful";
    }
    return "Login failed";
}

function authenticateUser($user, $pass) {
    // Mock authentication
    return ($user === "admin" && $pass === "secret");
}

// 20. Unsafe use of shell_exec with backticks
function backtickInjection() {
    $input = $_GET['input'];
    
    // Backtick operator executes shell commands
    $output = `ping -c 4 $input`;
    
    return $output;
}

// Test function to demonstrate vulnerabilities
function testAdditionalVulnerabilities() {
    if (isset($_GET['test'])) {
        $test = $_GET['test'];
        switch ($test) {
            case 'redirect':
                openRedirect();
                break;
            case 'ldap':
                ldapInjection();
                break;
            case 'xpath':
                xpathInjection();
                break;
            case 'response_split':
                httpResponseSplitting();
                break;
            case 'timing':
                timingAttack();
                break;
            case 'cookies':
                insecureCookies();
                break;
            case 'globals':
                unsafeGlobals();
                break;
            case 'reflection':
                reflectionInjection();
                break;
            case 'redos':
                redosVulnerability();
                break;
            case 'juggling':
                typeJuggling();
                break;
            case 'exec':
                execInjection();
                break;
            case 'billion_laughs':
                billionLaughs();
                break;
            case 'preg_replace':
                pregReplaceEval();
                break;
            case 'assert':
                assertInjection();
                break;
            case 'random':
                insecureRandom();
                break;
            case 'extract_skip':
                extractSkipVulnerability();
                break;
            case 'listing':
                directoryListing();
                break;
            case 'variable':
                variableVariableInjection();
                break;
            case 'password_url':
                passwordInUrl();
                break;
            case 'backtick':
                backtickInjection();
                break;
        }
    }
}

// Execute test if requested
testAdditionalVulnerabilities();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Additional PHP Vulnerabilities for Testing</title>
</head>
<body>
    <h1>Additional PHP Vulnerabilities for Testing</h1>
    <p>This file contains 20 additional security vulnerabilities for testing purposes.</p>
    <p>Use the "test" parameter with one of the following values to test specific vulnerabilities:</p>
    <ul>
        <li>redirect - Open Redirect</li>
        <li>ldap - LDAP Injection</li>
        <li>xpath - XPath Injection</li>
        <li>response_split - HTTP Response Splitting</li>
        <li>timing - Timing Attack</li>
        <li>cookies - Insecure Cookie Handling</li>
        <li>globals - Unsafe use of globals</li>
        <li>reflection - Reflection Injection</li>
        <li>redos - ReDoS Vulnerability</li>
        <li>juggling - Type Juggling</li>
        <li>exec - exec() Injection</li>
        <li>billion_laughs - Billion Laughs Attack</li>
        <li>preg_replace - preg_replace() with /e modifier</li>
        <li>assert - assert() Injection</li>
        <li>random - Insecure Randomness</li>
        <li>extract_skip - extract() with EXTR_SKIP</li>
        <li>listing - Directory Listing</li>
        <li>variable - Variable Variable Injection</li>
        <li>password_url - Password in URL</li>
        <li>backtick - Backtick Injection</li>
    </ul>
    
    <h2>Testing Forms</h2>
    
    <h3>LDAP Injection Test</h3>
    <form method="GET">
        <input type="hidden" name="test" value="ldap">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Test LDAP">
    </form>
    
    <h3>XPath Injection Test</h3>
    <form method="GET">
        <input type="hidden" name="test" value="xpath">
        Name: <input type="text" name="name"><br>
        <input type="submit" value="Test XPath">
    </form>
    
    <h3>Timing Attack Test</h3>
    <form method="POST">
        <input type="hidden" name="test" value="timing">
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Test Timing">
    </form>
</body>
</html>