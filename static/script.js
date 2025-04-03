const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendButton');
const attachmentInput = document.getElementById('attachmentInput');
const tosModal = document.getElementById('tosModal');
const acceptButton = document.getElementById('acceptButton');
const closeButton = document.getElementById('closeButton');

messageInput.addEventListener('input', function() {
    if (messageInput.value.trim()) {
        sendButton.style.display = 'inline-block';
    } else {
        sendButton.style.display = 'none';
    }
});

sendButton.addEventListener('click', function() {
    tosModal.style.display = 'block';
});

acceptButton.addEventListener('click', function() {
    const message = messageInput.value.trim();
    const files = attachmentInput.files;

    const formData = new FormData();
    formData.append("message", message);

    if (files.length > 0) {
        for (let i = 0; i < files.length; i++) {
            formData.append("messageAttachments", files[i]);
        }
    }

    fetch('/sendanonymousmessage', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        console.log('Message sent successfully:', data);
        messageInput.value = '';
        attachmentInput.value = '';
        sendButton.style.display = 'none';
        tosModal.style.display = 'none';
    })
    .catch(error => {
        console.error('Error sending message:', error);
    });
});

closeButton.addEventListener('click', function() {
    tosModal.style.display = 'none';
});
