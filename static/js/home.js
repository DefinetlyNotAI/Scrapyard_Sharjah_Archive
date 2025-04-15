document.addEventListener('DOMContentLoaded', (event) => {
    let startTime = localStorage.getItem('startTime');
    if (!startTime) {
        startTime = new Date().getTime().toString();
        localStorage.setItem('startTime', startTime);
    }
    let timerElement = document.getElementById('timer');

    function updateTimer() {
        let currentTime = new Date().getTime();
        let elapsedTime = currentTime - parseInt(startTime);
        let seconds = Math.floor((elapsedTime / 1000) % 60);
        let minutes = Math.floor((elapsedTime / (1000 * 60)) % 60);
        let hours = Math.floor((elapsedTime / (1000 * 60 * 60)) % 24);

        timerElement.innerHTML = `${hours.toString().padStart(2, '0')}h ${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`;
    }

    setInterval(updateTimer, 1000);
});