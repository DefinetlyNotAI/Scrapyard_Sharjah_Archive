const form = document.getElementById('signin-form');
const teamNameInput = document.getElementById('team_name');
const passwordInput = document.getElementById('password');
const errorMessage = document.getElementById('error-message') || document.getElementById('default-error-message');

// Add input validation on typing
teamNameInput.addEventListener('input', function () {
    if (this.value.trim() !== '') {
        errorMessage.classList.remove('visible');
    }
});

passwordInput.addEventListener('input', function () {
    if (this.value.trim() !== '') {
        errorMessage.classList.remove('visible');
    }
});

// Add focus effect
teamNameInput.addEventListener('focus', function () {
    this.parentElement.style.transform = 'scale(1.02)';
});

teamNameInput.addEventListener('blur', function () {
    this.parentElement.style.transform = 'scale(1)';
});

passwordInput.addEventListener('focus', function () {
    this.parentElement.style.transform = 'scale(1.02)';
});

passwordInput.addEventListener('blur', function () {
    this.parentElement.style.transform = 'scale(1)';
});

// Form submission handling
form.addEventListener('submit', function (event) {
    if (teamNameInput.value.trim() === '' || passwordInput.value.trim() === '') {
        event.preventDefault();
        errorMessage.textContent = "Please enter your team name and password.";
        errorMessage.classList.add('visible');
        teamNameInput.focus();

        // Add shake animation to input
        teamNameInput.style.animation = 'shake 0.5s';
        setTimeout(() => {
            teamNameInput.style.animation = '';
        }, 500);
    } else {
        errorMessage.classList.remove('visible');
    }
});

// Add shake animation
const style = document.createElement('style');
style.textContent = `
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-10px); }
            75% { transform: translateX(10px); }
        }
    `;
document.head.appendChild(style);
