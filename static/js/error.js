// Update timestamp for 403 error
const timestamp = document.getElementById('timestamp');
if (timestamp) {
    timestamp.textContent = new Date().toISOString();
}
