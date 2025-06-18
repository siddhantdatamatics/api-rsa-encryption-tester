const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const forge = require('node-forge');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Encrypt data using RSA and AES
app.post('/encrypt', (req, res) => {
    try {
        const { data, appPublicKey } = req.body;

        // Step 1: Generate AES key and IV
        const aesKey = forge.random.getBytesSync(32); // 256-bit AES key
        const iv = forge.random.getBytesSync(16); // 128-bit IV

        // Step 2: Encrypt the data using AES-GCM
        const cipher = forge.cipher.createCipher('AES-GCM', aesKey);
        cipher.start({ iv });
        cipher.update(forge.util.createBuffer(data));
        cipher.finish();
        const encryptedData = forge.util.encode64(cipher.output.getBytes()); // Base64 encode the encrypted data
        const authTag = forge.util.encode64(cipher.mode.tag.getBytes()); // Base64 encode the authentication tag

        // Step 3: Combine AES key, IV, and auth tag with a separator
        const aesKeyAndIvAndAuthTag = `${forge.util.encode64(aesKey)}:${forge.util.encode64(iv)}:${authTag}`;

        // Step 4: Convert PEM to Forge public key object
        const clientPublicKey = forge.pki.publicKeyFromPem(appPublicKey);

        // Step 5: Encrypt the combined AES key, IV, and auth tag using RSA-OAEP
        const encryptedKeyAndIvBytes = clientPublicKey.encrypt(aesKeyAndIvAndAuthTag, 'RSA-OAEP', {
            md: forge.md.sha256.create(), // Use SHA-256 for OAEP
        });
        const xEncryptedKey = forge.util.encode64(encryptedKeyAndIvBytes); // Base64 encode the encrypted AES key, IV, and auth tag

        // Step 6: Return the encrypted response
        res.json({
            xEncryptedKey,
            encryptedData,
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Decrypt data using RSA and AES
app.post('/decrypt', (req, res) => {
    try {
        const { xEncryptedKey, encryptedData, privateKey } = req.body;

        // Step 1: Convert PEM to Forge private key object
        const serverPrivateKey = forge.pki.privateKeyFromPem(privateKey);

        // Step 2: Decrypt the AES key, IV, and auth tag using RSA-OAEP
        const decryptedKeyAndIvBytes = serverPrivateKey.decrypt(forge.util.decode64(xEncryptedKey), 'RSA-OAEP', {
            md: forge.md.sha256.create(), // Use SHA-256 for OAEP
        });

        // Step 3: Split the decrypted string into AES key, IV, and auth tag
        const [aesKey, iv, authTag] = decryptedKeyAndIvBytes.split(':').map(forge.util.decode64);

        // Step 4: Decrypt the data using AES-GCM
        const decipher = forge.cipher.createDecipher('AES-GCM', aesKey);
        decipher.start({
            iv,
            tag: forge.util.createBuffer(authTag),
        });
        decipher.update(forge.util.createBuffer(forge.util.decode64(encryptedData)));
        const success = decipher.finish();

        if (!success) {
            throw new Error('Decryption failed');
        }

        // Step 5: Return the decrypted data
        res.json({ decryptedData: decipher.output.toString() });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start the server
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Encryption/Decryption server running on http://localhost:${PORT}`);
});
