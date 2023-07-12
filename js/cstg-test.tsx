import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

const getEcdhPublicKey = async () => {
    const pem = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsziOqRXZ7II0uJusaMxxCxlxgj8el/MUYLFMtWfB71Q3G1juyrAnzyqruNiPPnIuTETfFOridglP9UQNlwzNQg==";

    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pem);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);
    return window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false,
        // https://stackoverflow.com/questions/54179887/how-to-import-ecdh-public-key-cannot-create-a-key-using-the-specified-key-usage
        []);
};



const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);


handleEcdh();

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#subjectpublickeyinfo
// from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

// https://stackoverflow.com/a/9458996/
function _arrayBufferToBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}




function deriveSecretKey(privateKey, publicKey) {
    return window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey,
        },
        privateKey,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function handleEcdh() {
    console.log('Getting public key...');

    const serverPublicKey = await getEcdhPublicKey();

    performance.mark("cstg-start");

    console.log('Generating client key pair...');

    const clientKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false,
        ["deriveKey"]
    );

    console.log('Deriving secret key...');

    const sharedKey = await deriveSecretKey(
        clientKeyPair.privateKey,
        serverPublicKey
    );

    console.log('Exporting public key...');

    const exportedPublicKey: ArrayBuffer = await window.crypto.subtle.exportKey("spki", clientKeyPair.publicKey)

    // iv will be needed for decryption
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    console.log('Encrypting email...');

    const encryptedEmail: ArrayBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sharedKey,
        str2ab("test@example.com"));

    const body = {
        email: _arrayBufferToBase64(encryptedEmail),
        iv: _arrayBufferToBase64(iv),
        subscription_id: "abcdefg",
        publicKey: _arrayBufferToBase64(exportedPublicKey)
    };

    console.log('Generating token...');

    performance.mark("generate-token-start");

    const response = await fetch('http://localhost:8180/v2/token/client-generate', {
        method: 'POST',
        body: JSON.stringify(body),
    });

    performance.mark("generate-token-end");

    performance.measure("generate-token-duration", "generate-token-start", "generate-token-end");

    if (response.status !== 200) {
        console.log("Error response: " + response.statusText);
        return;
    }
    const base64ResponseBody = await response.text();
    const encryptedResponseBody: string = window.atob(base64ResponseBody);

    console.log('Decrypting response...');

    const responseBodyArrayBuffer = str2ab(encryptedResponseBody);

    console.log(responseBodyArrayBuffer);

    const decryptedResponseBody: ArrayBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: responseBodyArrayBuffer.slice(0, 12) },
        sharedKey,
        responseBodyArrayBuffer.slice(12),
    );

    const decryptedResponseBodyText = new TextDecoder().decode(decryptedResponseBody);

    console.log('response: %s', decryptedResponseBodyText);

    performance.mark("cstg-end");

    performance.measure("cstg-duration", "cstg-start", "cstg-end");
}

