document.addEventListener('DOMContentLoaded', function () {
    const fileInput = document.getElementById('file');
    const submitButton = document.querySelector('button[type="submit"]');

    fileInput.addEventListener('change', function () {
        submitButton.disabled = fileInput.files.length <= 0;
    });
});