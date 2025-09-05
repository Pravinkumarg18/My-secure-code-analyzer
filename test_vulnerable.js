// Test file with vulnerabilities
eval("alert('xss')");
innerHTML = "<script>alert('xss')</script>";
console.log("debug");
localStorage.setItem("token", "secret");
