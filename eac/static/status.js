const urlQuery = new URLSearchParams(window.location.search)
if (urlQuery.has('status')) {
    const status = urlQuery.get('status')
    const statusTitle = urlQuery.get('status-title')

    const modalEl = document.querySelector('#statusModal')
    const modal = new bootstrap.Modal(modalEl)

    const modalCloseBtn = modalEl.querySelector('#statusCloseButton')
    modalCloseBtn.addEventListener('click', () => modal.hide())

    const modalTitle = modalEl.querySelector('.modal-title')
    modalTitle.append(statusTitle)

    const modalBody = modalEl.querySelector('.modal-body')
    modalBody.append(status)

    modal.show()
}

