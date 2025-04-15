// noinspection JSUnresolvedReference

document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');
    form.addEventListener('submit', function (event) {
        const flagInput = document.getElementById('flag');
        if (flagInput.value.trim() === '') {
            event.preventDefault();
            swal({
                title: "Error",
                text: "Please enter a flag.",
                icon: "warning",
                button: "OK",
            });
        }
    });
});
