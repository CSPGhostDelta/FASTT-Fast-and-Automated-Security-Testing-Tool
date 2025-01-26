function startScan(event, form) {
    event.preventDefault();
    const targetId = form.getAttribute('data-target-id');
    const scanButton = form.querySelector('button[type="submit"]');
    
    fetch(form.action, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
    })
    .then(response => {
        if (response.ok) {
            setTimeout(() => {
                location.reload();
            }, 1000);
        } else {
            return response.json().then(errorData => {
                throw new Error(errorData.message || 'Failed to start scan');
            });
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        showToast(error.message || 'Failed to start scan. Please try again.', 'error');
        
        // Re-enable the scan button
        scanButton.disabled = false;
        scanButton.innerHTML = 'Start Scan';
    });
}

function pollScanStatus(targetId) {
    const statusElement = document.getElementById(`status-${targetId}`);
    const progressElement = document.getElementById(`progress-${targetId}`);

    let pollCount = 0;
    const maxPollAttempts = 300; 

    const intervalId = setInterval(() => {
        pollCount++;

        if (pollCount >= maxPollAttempts) {
            clearInterval(intervalId);
            showToast('Scan status check timed out', 'error');
            return;
        }

        fetch(`/scan_status/${targetId}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to fetch scan status');
                }
                return response.json();
            })
            .then(data => {
                // Update the status text
                statusElement.querySelector('span').textContent = data.status;

                // Update the progress
                if (data.status === 'Scanning') {
                    progressElement.style.display = 'inline';
                    progressElement.textContent = `(${data.progress}%)`;
                } else {
                    progressElement.style.display = 'none'; // Hide progress if not scanning
                }

                if (data.status === 'Completed' || data.status === 'Scan Error') {
                    clearInterval(intervalId);
                    setTimeout(() => {
                        location.reload(); 
                    }, 1000);
                }
            })
            .catch(error => {
                console.error('Error fetching scan status:', error);
                clearInterval(intervalId);
                showToast('Failed to check scan status', 'error');
            });
    }, 2000);
}

window.onload = function() {
    const flashMessages = document.getElementById('flash-messages');
    if (flashMessages && flashMessages.dataset.message) {
        showToast(flashMessages.dataset.message, flashMessages.dataset.category || 'success');
    }

    const targetElements = document.querySelectorAll('[id^="status-"]');
    targetElements.forEach(element => {
        const id = element.id.split('-')[1];
        const currentStatus = element.querySelector('span').textContent.trim();
    
        if (currentStatus === 'Scanning' || currentStatus === 'Scan Error') {
            pollScanStatus(id);
        }
    });
}
