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
    console.log(message)
    if(message.length > 500){
        alert("Maksymalna ilość znaków to 500.");
    }  

    const captchaToken = document.getElementsByName("cf-turnstile-response")[0].value;

    const payload = {
        'message': message,
        'cf-turnstile-response': captchaToken  // dodajemy token do payloadu
    };

    console.log(payload)
    

    fetch('/sendanonymousmessage', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload),
    })
    .then(response => response.json())
    .then(data => {
        console.log('server response:', data);
        if(data.antyboterror){
            console.log("antybot error");
            document.getElementById("captchaerror").textContent = "Potwierdz Captche";
        }else{
            messageInput.value = '';
            sendButton.style.display = 'none';
            window.location.href = '/';
        }
    })
    .catch(error => {
        console.error('Error sending message:', error);
    });
}

