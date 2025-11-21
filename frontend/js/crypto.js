(function (window) {
    "use strict";

    var API_BASE = "/notes/api";

    var cryptoSaltB64 = null;
    var dekForUserB64 = null;
    var dekRaw = null;         // Uint8Array med 32 byte DEK
    var ready = false;

    // --- Base64 helpers ---

    function b64ToBytes(b64) {
        var bin = atob(b64);
        var len = bin.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            bytes[i] = bin.charCodeAt(i);
        }
        return bytes;
    }

    function bytesToB64(bytes) {
        var bin = "";
        for (var i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin);
    }

    // --- Intern: hent /crypto/config ---

    function fetchCryptoConfig() {
        return fetch(API_BASE + "/crypto/config", {
            method: "GET",
            credentials: "include"
        }).then(function (resp) {
            if (resp.status === 401) {
                window.location.href = "/notes/login.html";
                return Promise.reject(new Error("Unauthorized"));
            }
            if (!resp.ok) {
                return resp.text().then(function (t) {
                    throw new Error("Klarte ikke å hente krypto-konfig: " + t);
                });
            }
            return resp.json();
        }).then(function (data) {
            cryptoSaltB64 = data.crypto_salt_b64;
            dekForUserB64 = data.dek_for_user_b64;
            return data;
        });
    }

    // --- Intern: derivér KEK fra passord + salt ---

    function deriveKEKFromPassword(password) {
        var enc = new TextEncoder();
        return window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        ).then(function (pwdKey) {
            var saltBytes = b64ToBytes(cryptoSaltB64);
            return window.crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: saltBytes,
                    iterations: 200000,
                    hash: "SHA-256"
                },
                pwdKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt", "decrypt"]
            );
        });
    }

    // --- Offentlig: init med passord (henter/genererer DEK) ---

    function initWithPassword(password) {
        ready = false;
        dekRaw = null;

        return fetchCryptoConfig().then(function () {
            return deriveKEKFromPassword(password);
        }).then(function (kekKey) {
            if (dekForUserB64) {
                // Dekrypter eksisterende DEK
                var full = b64ToBytes(dekForUserB64);
                var iv = full.slice(0, 12);       // 12-byte nonce
                var ct = full.slice(12);

                return window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    kekKey,
                    ct
                ).then(function (dekBuf) {
                    dekRaw = new Uint8Array(dekBuf);
                });
            } else {
                // Generer ny DEK og lagre kryptert på server
                dekRaw = new Uint8Array(32);
                window.crypto.getRandomValues(dekRaw);

                var ivNew = new Uint8Array(12);
                window.crypto.getRandomValues(ivNew);

                return window.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: ivNew },
                    kekKey,
                    dekRaw
                ).then(function (ctBuf) {
                    var ctBytes = new Uint8Array(ctBuf);
                    var full = new Uint8Array(ivNew.length + ctBytes.length);
                    full.set(ivNew, 0);
                    full.set(ctBytes, ivNew.length);

                    var fullB64 = bytesToB64(full);

                    return fetch(API_BASE + "/crypto/dek", {
                        method: "POST",
                        credentials: "include",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ dek_for_user_b64: fullB64 })
                    }).then(function (resp) {
                        if (!resp.ok) {
                            return resp.text().then(function (t) {
                                throw new Error("Klarte ikke å lagre DEK: " + t);
                            });
                        }
                        dekForUserB64 = fullB64;
                    });
                });
            }
        }).then(function () {
            ready = true;
        });
    }

    // --- Offentlig: sjekk om crypto er klar ---

    function isReady() {
        return ready && dekRaw !== null;
    }

    // --- Offentlig: krypter notat med DEK (AES-GCM) ---

    function encryptNote(plaintext) {
        if (!isReady()) {
            return Promise.reject(new Error("Kryptering ikke låst opp."));
        }

        var dekKeyPromise = window.crypto.subtle.importKey(
            "raw",
            dekRaw,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        var iv = new Uint8Array(12);
        window.crypto.getRandomValues(iv);
        var enc = new TextEncoder();

        return dekKeyPromise.then(function (dekKey) {
            return window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                dekKey,
                enc.encode(plaintext)
            );
        }).then(function (ctBuf) {
            var ctBytes = new Uint8Array(ctBuf);
            return {
                ciphertext_b64: bytesToB64(ctBytes),
                nonce_b64: bytesToB64(iv)
            };
        });
    }

    // --- Offentlig: dekrypter notat (AES-GCM) ---

    function decryptNote(ciphertext_b64, nonce_b64) {
        if (!ciphertext_b64 || !nonce_b64) {
            return Promise.resolve("[ingen data]");
        }

        if (!isReady()) {
            // Ikke feile – bare si at det er låst
            return Promise.resolve("[låst – skriv inn krypteringspassord]");
        }

        var dekKeyPromise = window.crypto.subtle.importKey(
            "raw",
            dekRaw,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        var iv = b64ToBytes(nonce_b64);
        var ct = b64ToBytes(ciphertext_b64);

        return dekKeyPromise.then(function (dekKey) {
            return window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                dekKey,
                ct
            );
        }).then(function (plainBuf) {
            var dec = new TextDecoder();
            return dec.decode(plainBuf);
        }).catch(function (err) {
            console.error("Feil ved dekryptering:", err);
            return "[kunne ikke dekryptere]";
        });
    }

    // Eksponer som globalt objekt
    window.CryptoNotes = {
        initWithPassword: initWithPassword,
        isReady: isReady,
        encryptNote: encryptNote,
        decryptNote: decryptNote
    };

})(window);