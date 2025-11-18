// vulnerable.js

function greetUser(username) {
    // This is a classic DOM-based XSS vulnerability
    document.getElementById("greeting").innerHTML = "Hello, " + username;
}

function unsafeEval(data) {
    // This is also a major security risk
    eval("console.log('" + data + "')");
}
