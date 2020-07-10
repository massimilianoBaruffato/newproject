$(window).on('load', function () {
    //funzione che chiama i metodi di click rispettivamente di authenticate e register
    //che viene  invocata quando si procede
    $("#register").on('click', () => registerButtonClicked());
    $("#authenticate").on('click', () => authenticateButtonClicked());

    //Update della ui per vedere se la identificazioni con autheticartor sia possibile
    if (PublicKeyCredential && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
        markPlatformAuthenticatorUnavailable();
    } else if (PublicKeyCredential && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(available => {
            if (!available) {
                markPlatformAuthenticatorUnavailable();
            }
        }).catch(e=>{
            markPlatformAuthenticatorUnavailable();
        });
    }
});

/**
 *Controllo che l'authenticazione sia possibile sul dispositivo
 */
function markPlatformAuthenticatorUnavailable() {
    $('label[for="attachmentPlatform"]').html('Authenticator non disponible</span>');
}



/**
 * Funzione di gestione quand oviene clikkato il pulsante register
 */
function registerButtonClicked() {
   
    getChallenge().then(challenge => {
        return createCredential(challenge);
    }).then(credential => {
        localStorage.setItem("credentialId", credential.id);
        $("#status").text("Successo create credenziali con id : " + credential.id);
    }).catch(e => {
        $("#status").text("Errore: " + e);
        
    });
}

/**
 * Funzione di gestione quando viene clikkato il pulsante authenticate
 */
function authenticateButtonClicked() {
   getChallenge().then(challenge => {
        return getAssertion(challenge);
    }).then(credential => {
        $("#status").text("Successo verifica credenziali Id: " + credential.id);
        }).catch(e => {
        $("#status").text("Errore: " + e);
      
    });
}

/**
 * recupera la challenge dal server
 * Ritorna una promise per risolvere ad un ArrayBuffer challenge
 */
function getChallenge() {
    return rest_get(
        "/challenge"
    ).then(response => {
        if (response.error) {
            return Promise.reject(error);
        }
        else {
            var challenge = stringToArrayBuffer(response.result);
            return Promise.resolve(challenge);
        }
    });
}

/**
 * chiama la .create() di webauthn APIs e manda il returns al server
 */
function createCredential(challenge) {
    if (!PublicKeyCredential || typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function")
        return Promise.reject("WebAuthn non è disponibile.");

    var attachment = $("input[name='attachment']:checked").val();

    var createCredentialOptions = {
        rp: {
            name: "WebAuthn applicazione"
        },
        user: {
            id: stringToArrayBuffer("some.user.id"),
            name: "max@gmail.com",
            displayName: "Max baruffato"
        },
        pubKeyCredParams: [
            {
                //autenticazione esterna che supporta lo ES256 algoritmo
                type: "public-key",
                alg: -7                 
            }, 
            {
                //windows hello
                type: "public-key",
                alg: -257
            }
        ],
        authenticatorSelection: {
            //selezione l'authenticator che supporta username-less flows
            requireResidentKey: true,
            //Selezione un autjemticatore che ha il formato di un second factor (PIN, Bio)
            userVerification: "required",
            authenticatorAttachment: attachment
        },
        
        timeout: 50000,
        challenge: challenge,
        excludeCredentials: [],
        attestation: "none"
    };

    //navigator.credential.create()
    return navigator.credentials.create({
        publicKey: createCredentialOptions
    }).then(rawAttestation => {
        var attestation = {
            id: base64encode(rawAttestation.rawId),
            name: base64encode(rawAttestation),
            clientDataJSON: arrayBufferToString(rawAttestation.response.clientDataJSON),
            attestationObject: base64encode(rawAttestation.response.attestationObject)
        };
        //console log di prova
        console.log("=== Attestation response ===");
        logVariable("id (base64)", attestation.id);
        logVariable("name(base64)",attestation.name);
        logVariable("clientDataJSON", attestation.clientDataJSON);
        logVariable("attestationObject (base64)", attestation.attestationObject);

        return rest_put("/credentials", attestation);
    }).then(response => {
        //controller eventuali errori
        if (response.error) {
            return Promise.reject(response.error);
        }// ritorno la Promise con il risultato 
        else {
            return Promise.resolve(response.result);
        }
    });
}

/**
 * Chiamo la get() API e la mando al server per il controllo
 */
function getAssertion(challenge) {
    if (!PublicKeyCredential)
        return Promise.reject("WebAuthn APIs non e disponibile")
    var allowCredentials = [];
    var allowCredentialsSelection = $("input[name='allowCredentials']:checked").val();

    if (allowCredentialsSelection === "filled") {
        var credentialId = localStorage.getItem("credentialId");

        if (!credentialId)
            return Promise.reject("Perfavore creare una credenziale prima");

        allowCredentials = [{
            type: "public-key",
            id: Uint8Array.from(atob(credentialId), c=>c.charCodeAt(0)).buffer
        }];
    }

    var getAssertionOptions = {
        //specifica quale credenziale puo essere usata per autenticare lo user
        allowCredentials: allowCredentials,
        //challenge
        challenge: challenge,
        timeout: 50000
    };

    // navigator .credential.get()
    return navigator.credentials.get({
        publicKey: getAssertionOptions
    }).then(rawAssertion => {
        var assertion = {
            id: base64encode(rawAssertion.rawId),
            clientDataJSON: arrayBufferToString(rawAssertion.response.clientDataJSON),
            userHandle: base64encode(rawAssertion.response.userHandle),
            signature: base64encode(rawAssertion.response.signature),
            authenticatorData: base64encode(rawAssertion.response.authenticatorData)
        };
        //controli vari con console log
        console.log("=== Assertion risposta ===");
        logVariable("id (base64)", assertion.id);
        logVariable("userHandle (base64)", assertion.userHandle);
        logVariable("authenticatorData (base64)", assertion.authenticatorData);
        logVariable("clientDataJSON", assertion.clientDataJSON);
        logVariable("signature (base64)", assertion.signature);

        return rest_put("/assertion", assertion);
    }).then(response => {
        if (response.error) {
            //controlo errori
            return Promise.reject(response.error);
        } else {
            return Promise.resolve(response.result);
        }
    });
}

/**
 *Base64 codifica un arraybuffer
 */
function base64encode(arrayBuffer) {
    if (!arrayBuffer || arrayBuffer.length == 0)
        return undefined;

    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}

/**
 *converte un array buffer in uan UTF8 string
 */
function arrayBufferToString(arrayBuffer) {
    return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

/**
 * Converte una stringa in un array buffer
 */
function stringToArrayBuffer(str){
    return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
}
/*
*console log di prova
*/
function logVariable(name, text) {
    console.log(name + ": " + text);
}

/**
 * performa unoperazioen con hhtp get
 */
function rest_get(endpoint) {
    return fetch(endpoint, {
        method: "GET",
        credentials: "same-origin"
    }).then(response => {
        return response.json();
    });
}

/**
 * performa una HTTP chiamata in put
 * e risolve la promise con un oggetto javascript ritornato
 */
function rest_put(endpoint, object) {
    return fetch(endpoint, {
        method: "PUT",
        credentials: "same-origin",
        body: JSON.stringify(object),
        headers: {
            "content-type": "application/json"
        }
    }).then(response => {
        return response.json();
    });
}
