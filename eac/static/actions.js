(function () {
    const reload = () => window.location.reload();
    const controls = document.querySelectorAll("button[data-service]");

    for (const control of controls) {
        const serviceName = control.dataset.service;
        const endpoint = serviceName;
        const unlink = control.dataset.action === "unlink";

        control.addEventListener('click', () => {
            for (const control of controls) {
                control.disabled = true;
            }

            if (unlink) {
                fetch(endpoint, {
                    method: "DELETE",
                    credentials: "same-origin"
                })
                    .then(reload)
                    .catch(reload);
            } else {
                const popup = window.open(endpoint, serviceName, "height=800,width=600");
                const timer = setInterval(() => {
                    if (popup.closed) {
                        clearInterval(timer);
                        reload();
                    }
                }, 500);
            }
        });
    }
}());
