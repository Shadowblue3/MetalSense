let currentLoginType = 'public';

function selectLoginType(type) {
    currentLoginType = type;
    // Update buttons
    document.getElementById('publicLoginBtn').classList.toggle('active', type === 'public');
    const govBtn = document.getElementById('governmentLoginBtn');
    if (govBtn) govBtn.classList.toggle('active', type === 'government');
    // Show/hide forms
    document.getElementById('publicLoginForm').classList.toggle('active', type === 'public');
    const govFormSec = document.getElementById('governmentLoginForm');
    if (govFormSec) govFormSec.classList.toggle('active', type === 'government');
    // Reset forms
    document.getElementById('publicForm').reset();
    if (document.getElementById('governmentForm')) document.getElementById('governmentForm').reset();
    document.querySelectorAll('.error-message').forEach(error => error.style.display = 'none');
}

function validatePublicLogin() {
    // Basic email and password checks (already required in markup)
    const email = document.getElementById('publicEmail').value.trim();
    const password = document.getElementById('publicPassword').value;
    return email.length > 0 && password.length > 0;
}

// remove official validation

async function performLogin(payload) {
    const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    
    const data = await res.json();
    if (data && data.success) {
        window.location.href = data.redirect || '/dashboard';
    } else {
        alert(data && data.message ? data.message : 'Login failed');
    }
}

function forgotPassword() {
    alert('Password reset link would be sent to your registered email address.');
}

function goToSignup() {
    // Browser goes to signup
}

// Event listeners

document.getElementById('publicForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    if (validatePublicLogin()) {
        const email = document.getElementById('publicEmail').value.trim();
        const password = document.getElementById('publicPassword').value;
        await performLogin({ type: 'public', publicEmail: email, password });
    }
});

if (document.getElementById('governmentForm')) {
  document.getElementById('governmentForm').addEventListener('submit', async function(e){
    e.preventDefault();
    const employeeId = document.getElementById('governmentEmployeeId').value.trim();
    const password = document.getElementById('governmentPassword').value;
    await performLogin({ type: 'government', governmentEmployeeId: employeeId, password });
  });
}

// Animate water drops
function animateDrops() {
    const drops = document.querySelectorAll('.water-drop');
    drops.forEach((drop, index) => { drop.style.animationDelay = `${index * 0.5}s`; });
}
animateDrops();

//toggle password
let ibtn1 = document.querySelector(".toggle-password")
document.querySelector(".toggle-password").addEventListener("click", ()=>{
    const elem = document.getElementById("publicPassword")
    
    if(elem.type === "text"){
        ibtn1.src = "/images/eye-off.svg"
        elem.type = "password"
    }
    else{
        ibtn1.src = "/images/eye.svg"
        elem.type = "text"
    }
})

let ibtn2 = document.querySelector(".toggle-password-off")
document.querySelector(".toggle-password-off").addEventListener("click", ()=>{
    const elem = document.getElementById("officialPassword")
    
    if(elem.type === "text"){
        ibtn2.src = "/images/eye-off.svg"
        elem.type = "password"
    }
    else{
        ibtn2.src = "/images/eye.svg"
        elem.type = "text"
    }
})