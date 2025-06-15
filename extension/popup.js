function checkPasswordStrength(password) {
    let strength = 0;
    let remarks = "";

    if (password.length >= 8) {
        strength += 1;
    } else {
        remarks += "❗ Password is too short. Must be at least 8 characters.\n";
    }

    if (/[a-z]/.test(password)) {
        strength += 1;
    } else {
        remarks += "❗ Add some lowercase letters.\n";
    }

    if (/[A-Z]/.test(password)) {
        strength += 1;
    } else {
        remarks += "❗ Add some uppercase letters.\n";
    }

    if (/\d/.test(password)) {
        strength += 1;
    } else {
        remarks += "❗ Add some numbers.\n";
    }

    if (/[\W_]/.test(password)) {
        strength += 1;
    } else {
        remarks += "❗ Add some special characters (!, @, #, etc.).\n";
    }

    if (strength === 5) {
        remarks = "✅ Password is Strong!";
    } else if (strength >= 3) {
        remarks = "⚠️ Password is Moderate.\n" + remarks;
    } else {
        remarks = "❌ Password is Weak!\n" + remarks;
    }

    return remarks;
}

document.getElementById("checkBtn").addEventListener("click", function() {
    const password = document.getElementById("passwordInput").value;
    const result = checkPasswordStrength(password);
    document.getElementById("result").innerText = result;
});
