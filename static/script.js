const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendButton');
const tosModal = document.getElementById('tosModal');
const acceptButton = document.getElementById('acceptButton');
const closeButton = document.getElementById('closeButton');

if (getCookie('accepted_tos') !== 'true') {
    tosModal.style.display = 'block';
} else {
    tosModal.style.display = 'none';
}

messageInput.addEventListener('input', function() {
    if (messageInput.value.trim()) {
        sendButton.style.display = 'inline-block';
    } else {
        sendButton.style.display = 'none';
    }
});

sendButton.addEventListener('click', function() {
    if (getCookie('accepted_tos') !== 'true') {
        tosModal.style.display = 'block';
    } else {
        sendMessage();
    }
});

acceptButton.addEventListener('click', function() {
    setCookie('accepted_tos', 'true', 365);

    tosModal.style.display = 'none';

    sendMessage();
});

closeButton.addEventListener('click', function() {
    tosModal.style.display = 'none';
});

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function setCookie(name, value, days) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = `expires=${date.toUTCString()}`;
    document.cookie = `${name}=${value}; ${expires}; path=/`;
}

function sendMessage() {
    const message = messageInput.value.trim();

    const payload = {
        message: message
    };

    fetch('/sendanonymousmessage', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })
    .then(response => response.json())
    .then(data => {
        console.log('Message sent successfully:', data);
        messageInput.value = '';
        sendButton.style.display = 'none';
    })
    .catch(error => {
        console.error('Error sending message:', error);
    });
}

