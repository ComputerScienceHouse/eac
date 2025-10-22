function showModal(statusTitle, status) {
    const modalEl = document.querySelector('#statusModal')
    const modal = new bootstrap.Modal(modalEl)

    const modalCloseBtn = modalEl.querySelector('#statusCloseButton')
    modalCloseBtn.addEventListener('click', () => modal.hide())

    const modalTitle = modalEl.querySelector('.modal-title')
    modalTitle.append(statusTitle)

    const modalBody = modalEl.querySelector('.modal-body')
    modalBody.append(status)

    modalEl.addEventListener('hidden.bs.modal', window.location.reload)

    modal.show()

    return modal;
}

window.addEventListener('load', () => {
    const controls = document.querySelectorAll("button[data-service]");
    const reload = () => window.location.reload();

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
                    try {
                        if (popup.location.pathname == '/status') {
                            clearInterval(timer)

                            const query = new URLSearchParams(popup.location.search)
                            popup.close()

                            const statusTitle = query.get('status-title')
                            const status = query.get('status')

                            showModal(statusTitle, status)
                        }
                    } catch {
                        // do this because every time you try and access the location of a window with a different origin it errors
                    }
                }, 500);
            }
        });
    }
});
