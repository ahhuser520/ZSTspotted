// utils.js

async function encrypt(data, key) {
    console.log("Encrypting data...");

    // Normalizacja klucza
    const normalizedKey = new TextEncoder().encode(key.padEnd(32, '0').slice(0, 32));
    console.log("Normalized key: ", normalizedKey);

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        normalizedKey,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    // Funkcja pomocnicza do szyfrowania pojedynczego fragmentu
    async function encryptChunk(chunk, keyMaterial) {
        try {
            // Generowanie IV (losowy 12-bajtowy)
            const iv = crypto.getRandomValues(new Uint8Array(12));

            // Szyfrowanie fragmentu
            const encryptedBuffer = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                keyMaterial,
                new TextEncoder().encode(chunk)
            );

            // Zwracamy połączony wynik: IV + zaszyfrowany fragment
            const encryptedData = new Uint8Array(iv.length + encryptedBuffer.byteLength);
            encryptedData.set(iv);
            encryptedData.set(new Uint8Array(encryptedBuffer), iv.length);

            return encryptedData;
        } catch (err) {
            console.error("Error encrypting chunk:", err);
            throw err;
        }
    }

    // Podziel dane na części (dzielimy na podstawie '|')
    const chunks = data.split('|');
    console.log("Chunks to encrypt:", chunks);

    // Szyfrowanie każdego fragmentu
    const encryptedChunks = [];
    for (const chunk of chunks) {
        const encryptedChunk = await encryptChunk(chunk, keyMaterial);
        encryptedChunks.push(encryptedChunk);
    }

    // Łączenie zaszyfrowanych fragmentów w jeden ciąg (z separatorami '|')
    let encryptedData = encryptedChunks.map(chunk => base64EncodeUint8Array(chunk)).join('|');
    console.log("Encrypted data:", encryptedData);

    return encryptedData;
}

function base64EncodeUint8Array(array) {
    const binaryString = Array.from(array, byte => String.fromCharCode(byte)).join('');
    return btoa(binaryString);
}

function base64ToBuffer(base64) {
    try {
        console.log("utils.js, base64ToBuffer(), Base64 data before conversion:", base64);
        const binaryString = atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        console.log("utils.js, base64ToBuffer(), Conversion from Base64 to ArrayBuffer completed successfully.");
        return bytes.buffer;
    } catch (error) {
        console.error("utils.js, base64ToBuffer(), Error during Base64 to ArrayBuffer conversion:", error.message);
        throw new Error("utils.js, base64ToBuffer(), Invalid Base64 string. Ensure the data is encoded correctly.");
    }
}
async function decrypt(encryptedData, key) {
    console.log("Decrypting data...");

    // Normalizacja klucza
    const normalizedKey = new TextEncoder().encode(key.padEnd(32, '0').slice(0, 32));
    console.log("Normalized key: ", normalizedKey);

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        normalizedKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    // Funkcja pomocnicza do deszyfrowania pojedynczego fragmentu
    async function decryptChunk(chunk, keyMaterial) {
        try {
            // IV (pierwsze 12 bajtów bloku)
            const iv = chunk.slice(0, 12);
            const encryptedChunk = chunk.slice(12);

            // Deszyfrowanie fragmentu
            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                keyMaterial,
                encryptedChunk
            );

            // Zwracamy odszyfrowany tekst
            return new TextDecoder().decode(decryptedBuffer);
        } catch (err) {
            console.error("Error decrypting chunk:", err);
            throw err;
        }
    }

    // Podziel dane na części (rozdzielamy na podstawie '|')
    const chunks = encryptedData.split('|');
    console.log("Chunks to decrypt:", chunks);

    // Deszyfrowanie każdego fragmentu
    const decryptedChunks = [];
    for (const chunk of chunks) {
        const chunkArray = base64DecodeToUint8Array(chunk);
        const decryptedChunk = await decryptChunk(chunkArray, keyMaterial);
        decryptedChunks.push(decryptedChunk);
    }

    // Łączenie odszyfrowanych fragmentów
    const decryptedData = decryptedChunks.join('|');
    console.log("Decrypted data:", decryptedData);

    return decryptedData;
}

async function hash(data) {
    console.log("utils.js, hash(), Hashing data: " + data);
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    const hashBuffer = await crypto.subtle.digest("SHA-512", dataBuffer);

    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    return hashHex;
}

async function hashPassword(pass, salt) {
    console.log("Hashing password:", pass, "with salt:", salt);

    // Combine password and salt
    const combined = new TextEncoder().encode(pass + salt);

    // Generate SHA-512 hash
    const hashBuffer = await crypto.subtle.digest('SHA-512', combined);

    // Convert hash to hexadecimal string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    return hashHex;
}

async function sendJsonRequest(url, data) {
    console.log("utils.js, sendJsonRequest(), Request payload:", data);
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        try{
            document.getElementById("connectionError").style.display = "none";
        }catch(error){
            console.log("utils.js, sendJsonRequest(), div 'connectionError' does not exist." )
        }
        // return JSON object
        return response;
    } catch (error) {
        console.error('utils.js, sendJsonRequest(), Error during the request:', error);
        if (error instanceof TypeError && error.message === 'Failed to fetch') {
            try{
                document.getElementById("connectionError").style.display = "block";
            }catch(error){
                console.log("utils.js, sendJsonRequest(), div 'connectionError' does not exist." )
            }
            throw new Error('errConnection');
        }
        throw error;
    }
}

function generateRandomString(n) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < n; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

async function hashSHA256(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);

    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    return hashHex;
}

function setSecureCookie(name, value, days) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = "expires=" + date.toUTCString();
    document.cookie = `${name}=${value}; ${expires}; path=/; Secure; SameSite=Strict`; //HttpOnly;
}

function setSecureData(name, value) {
    localStorage.setItem(name, value);
}

function getSecureData(name) {
    const data = localStorage.getItem(name);
    return data;
}

function getSecureCookie(name) {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.startsWith(name + '=')) {
            return cookie.substring(name.length + 1);
        }
    }
    return null;
}

//const url = "http://51.77.48.176:4800/api/";
const url = "https://zstspotted.pl/api/";
export { hash, encrypt, sendJsonRequest, decrypt, hashPassword, hashSHA256, url, setSecureCookie, getSecureCookie, setSecureData, getSecureData, generateRandomString };