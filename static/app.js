function hashText() {
    const text = document.getElementById('sha256-input').value;
    fetch('/api/hash', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('sha256-result').innerText = `SHA-256: ${data.hash}`;
    })
    .catch(error => {
        document.getElementById('sha256-result').innerText = 'Error hashing text.';
    });
}

function lookupDNS() {
    const domain = document.getElementById('dns-input').value;
    fetch(`/api/dns?domain=${domain}`)
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            document.getElementById('dns-result').innerText = `IP Addresses: ${data.ip_addresses.join(', ')}`;
        } else {
            document.getElementById('dns-result').innerText = 'Error looking up DNS.';
        }
    })
    .catch(error => {
        document.getElementById('dns-result').innerText = 'Error looking up DNS.';
    });
}

function generatePassword() {
    const length = document.getElementById('password-length').value;
    fetch(`/api/password?length=${length}`)
    .then(response => response.json())
    .then(data => {
        document.getElementById('password-result').innerText = `Password: ${data.password}`;
    })
    .catch(error => {
        document.getElementById('password-result').innerText = 'Error generating password.';
    });
}