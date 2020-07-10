const base64url = require('base64url');
//Encode e parse data per Concise Binary Object Representation
const cbor = require('cbor');
//modulo per parse e unparsed di un UUID
const uuid = require('uuid-parse');
const jwkToPem = require('jwk-to-pem');
//modulo perl a crezione di token web con formato json
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const url = require('url');

const storage = require('./storage.js');

const hostname = process.env.HOSTNAME || "localhost";
const jwt_secret = process.env.JWT_SECRET || "defaultsecret";


const fido = {};

/**
 Prende uan challenge dal client
 Internamente questa challenge e rappresentata da un jwt con un timeout
 */
fido.getChallenge = () => {
    return jwt.sign({}, jwt_secret, {
        expiresIn: 120 * 1000
    });
};

/*
 Crea credenziali fido 
 */
fido.makeCredential = async (attestation) => {
    //controlli su quello che viene passato
    if (!attestation.id)
        throw new Error("id mancante");
    if (!attestation.attestationObject)
        throw new Error("attestationObject mancante")
    if (!attestation.clientDataJSON)
        throw new Error("clientDataJSON mancante");

    //Parse delle informazione che vengono ricevute dal client
    //nella parte di creazione delle credenziali
    let C;
    try {
        C = JSON.parse(attestation.clientDataJSON);
    } catch (e) {
        //controllo che non ci siano errori nella parsificazione del file json
        throw new Error("clientDataJSON nonp uo essere parsato");
    }

    //verifica client data
    validateClientData(C, "webauthn.create");
    //Computazione del file json usando SHA-256.
    const clientDataHash = sha256(attestation.clientDataJSON);

    //Utilizzo di cbor per decodificare l'attestazion object
    let attestationObject;
    try {
        attestationObject = cbor.decodeFirstSync(Buffer.from(attestation.attestationObject, 'base64'));
    } catch (e) {
        //controllo se i lfile puo essere decodificato
        throw new Error("attestationObject non puo essere decodificato");
    }
    //Parsificazione authData dentro attestationObject
    const authenticatorData = parseAuthenticatorData(attestationObject.authData);
    //authenticatorData dovrebbe contenere attestedCredentialData
    if (!authenticatorData.attestedCredentialData)
        throw new Exception("non ho visto AD flag in authenticatorData");

    //Step 9: verifico che il relaying party id sia effettivamente SHA-256 hash
    //dell'id Relaying party del replaying party.
    if (!authenticatorData.rpIdHash.equals(sha256(hostname))) {
        throw new Error("RPID hash non matcha il valore: sha256(" + rpId + ")");
    }

    //Step 10: Verifico che lo User Present bit del flags in authData sia settato
    if ((authenticatorData.flags & 0b00000001) == 0) {
        throw new Error("User Present bit non trovato");
    }

    //Step 11: Verifico che lo User Verified bit del flags in authData sia settato
    if ((authenticatorData.flags & 0b00000100) == 0) {
        throw new Error("User Verified bit non è stato settato.");
    }


    //Store  delle credenziali
    const credential = await storage.Credentials.create({
        id: authenticatorData.attestedCredentialData.credentialId.toString('base64'),
        name: authenticatorData.attestedCredentialData.nameId.toString('base64'),
        publicKeyJwk: authenticatorData.attestedCredentialData.publicKeyJwk,
        signCount: authenticatorData.signCount
    });

    return credential;
};