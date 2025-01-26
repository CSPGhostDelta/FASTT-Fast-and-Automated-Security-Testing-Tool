function enableButton() {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginButton = document.getElementById('loginbtn');
    if (usernameInput.value.trim() && passwordInput.value.trim()) {
        loginButton.disabled = false;
    } else {
        loginButton.disabled = true;
    }
}

function showpassword() {
    const passwordInput = document.getElementById('password');
    passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
}

function showToast(message, category) {
    const toast = document.createElement('div');
    toast.className = `toast ${category}`;
    toast.innerText = message;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('show');
    }, 100);

    setTimeout(() => {
        toast.classList.remove('show');
        toast.classList.add('fade-out');
        toast.addEventListener('animationend', () => toast.remove());
    }, 3500);
}

window.onload = function() {
    const flashMessages = document.getElementById("flash-messages");
    if (flashMessages) {
        const message = flashMessages.getAttribute('data-message');
        const category = flashMessages.getAttribute('data-category');
        showToast(message, category);
    }
};

function darkmode() {
    const darkButton = document.getElementById('darkbutton');
    const body = document.body;
    if (darkButton.checked) {
        body.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
    } else {
        body.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme');
    const darkButton = document.getElementById('darkbutton');
    
    if (savedTheme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        darkButton.checked = true;
    } else {
        document.body.removeAttribute('data-theme');
        darkButton.checked = false;
    }
});

function toggleProfileOptions() {
    const profileOptions = document.getElementById('profileOptions');
    if (profileOptions.style.display === "none") {
        profileOptions.style.display = "block";
    } else {
        profileOptions.style.display = "none";
    }
}

function confirmDelete(event, form) {
    event.preventDefault();
    Swal.fire({
        title: 'Are you sure?',
        text: "You won't be able to revert this!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, delete it!'
    }).then((result) => {
        if (result.isConfirmed) {
            form.submit(); 
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    const table = document.querySelector('.vulnerabilities table');
    const headers = table.querySelectorAll('th.sortable');

    headers.forEach(header => {
        const sortIcon = header.querySelector('.sort-icon');
        
        if (sortIcon) {
            header.addEventListener('click', () => {
                const columnIndex = Array.from(table.querySelectorAll('th')).indexOf(header);
                const currentOrder = header.getAttribute('data-order') || 'asc';
                const newOrder = currentOrder === 'asc' ? 'desc' : 'asc';

                // Reset other sortable headers' order
                headers.forEach(h => {
                    const icon = h.querySelector('.sort-icon');
                    if (h !== header) {
                        h.removeAttribute('data-order');
                        if (icon) {
                            icon.classList.remove('asc', 'desc');
                        }
                    }
                });

                // Mark current header
                header.setAttribute('data-order', newOrder);
                
                // Update icon for current header
                sortIcon.classList.remove('asc', 'desc');
                sortIcon.classList.add(newOrder);

                sortTable(table, columnIndex, newOrder);
            });
        }
    });
});

function sortTable(table, columnIndex, order) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    const sortedRows = rows.sort((a, b) => {
        if (columnIndex === 0) { // Assuming "No." is the first column (index 0)
            const indexA = parseInt(a.cells[0].textContent.trim(), 10);
            const indexB = parseInt(b.cells[0].textContent.trim(), 10);
            return order === 'asc' ? indexA - indexB : indexB - indexA;
        } else {
            const cellA = a.querySelectorAll('td')[columnIndex].textContent.trim();
            const cellB = b.querySelectorAll('td')[columnIndex].textContent.trim();

            // Special handling for severity
            if (columnIndex === 3) {  // Assuming Severity is the 4th column (index 3)
                const severityOrder = {
                    'Critical': 1,
                    'High': 2,
                    'Medium': 3,
                    'Low': 4,
                    'Informational': 5
                };

                const valueA = severityOrder[cellA] || 6;
                const valueB = severityOrder[cellB] || 6;

                return order === 'asc' ? valueA - valueB : valueB - valueA;
            }

            // Default string comparison for other columns
            return order === 'asc' 
                ? cellA.localeCompare(cellB) 
                : cellB.localeCompare(cellA);
        }
    });

    // Clear and repopulate tbody
    tbody.innerHTML = '';
    sortedRows.forEach(row => tbody.appendChild(row));
}