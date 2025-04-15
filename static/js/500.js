// Generate random binary code in the background
// noinspection JSUnresolvedReference

function generateErrorCode() {
    const errorCode = document.querySelector('.error-code');
    setInterval(() => {
        errorCode.textContent = Array.from({length: 8}, () =>
            Math.random() > 0.5 ? '1' : '0'
        ).join('');
    }, 100);
}

function retryConnection() {
    const btn = document.querySelector('.retry-btn');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Retrying...';

    // Add more glitch effect during retry
    document.querySelector('.server').style.animation = 'server-shake 0.2s ease-in-out infinite';

    setTimeout(() => {
        btn.disabled = false;
        btn.textContent = originalText;
        document.querySelector('.server').style.animation = 'server-shake 0.5s ease-in-out infinite';

        // Attempt to retry the request
        fetch(`/retry/${encodeURIComponent(window.location.href)}`, {method: 'POST'})
            .then(response => response.json().then(data => ({status: response.status, body: data}))) // Parse JSON
            .then(({status, body}) => {
                if (status === 200) {
                    Swal.fire({
                        icon: 'success',
                        title: 'Retry Successful!',
                        text: `Response: ${body.message}`,
                    });
                } else {
                    throw body; // Pass the error object for handling below
                }
            })
            .catch(error => {
                console.error('Retry failed:', error);
                Swal.fire({
                    icon: 'error',
                    title: 'Retry failed',
                    text: error.error_message || 'An unknown error occurred.',
                });

                // Update error display
                setTimeout(() => {
                    const errorMessages = [
                        "Critical system failure: Too many cats in the database!",
                        "Error 500: Server turned into a toaster",
                        "Quantum fluctuation detected in the coffee machine",
                        "Server.exe has stopped working... and started dancing",
                        "Emergency: CPU needs a vacation!",
                        "System.out.of.cheese.error",
                        "HTTP 500: Server is having an existential crisis",
                        "Well this is embarrassing... Server is on strike",
                        "Server is on fire, send a Halo-carbon fire extinguisher",
                        "Server is busy playing Minecraft",
                        "Server is too busy watching cat videos",
                        "Server is feeling a bit under the weather",
                    ];

                    const errorDetails = [
                        "MAXIMUM_CALL_STACK_SIZE_EXCEEDED",
                        "UNEXPECTED_TOKEN_UNICORN",
                        "NULL_POINTER_EXCEPTION",
                        "DIVISION_BY_ZERO",
                        "MEMORY_OVERFLOW",
                        "SYNTAX_ERROR_EXPECTED_SEMICOLON_GOT_PIZZA",
                    ];

                    document.querySelector('.description').textContent =
                        errorMessages[Math.floor(Math.random() * errorMessages.length)];

                    document.querySelector('.error-details').innerHTML =
                        `<span>Error: ${error.error_code || "INTERNAL_SERVER_ERROR"}</span><br>
                        <span>Status: ${error.status_code || 500}</span><br>
                        <span>Stack: ${errorDetails[Math.floor(Math.random() * errorDetails.length)]}</span>`;
                }, 1000);
            });
    }, 1000);
}

// Initialize the page
document.addEventListener('DOMContentLoaded', () => {
    generateErrorCode();
});