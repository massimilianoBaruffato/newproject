//Require pacchetti Utilizzati
const express = require("express");
const app = express();
const fido = require('./fido.js');
const bodyParser = require('body-parser');

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


// Definizione die vari percorsi
app.get('/challenge', async (req, res) => {
    try {
        //chiamata a fido challenge
        const challenge = await fido.getChallenge();
        res.json({
            result: challenge
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    };
});

app.put('/credential', async (req, res) => {
    try {
        //chiamata a makecredential
        const credential = await fido.makeCredential(req.body);
        res.json({
            result: credential
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    }
});

app.put('/assertion', async (req, res) => {
    try {
        //chiamata a verify assertion
        const credential = await fido.verifyAssertion(req.body);
        res.json({
            result: credential
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    }
});


//app listen su porta 3000 di localhost
app.listen(process.env.PORT || 3000, () => console.log('Applicazione partita.'));