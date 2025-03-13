const cose = require('cose-js');
const fs = require('fs');
const pako = require('pako');
const base45 = require('base45-js');
const cbor = require('cbor');
const { PEM } = require('@fidm/asn1');

// Leer mensaje firmado desde stdin
const buffer = Buffer.alloc(4096);
const len = fs.readSync(process.stdin.fd, buffer, 0, buffer.length);
const input = buffer.slice(0, len).toString().trim();

// Quitar prefijo "s6JzcMj5iQ:" y decodificar
const encoded = input.replace(/^s6JzcMj5iQ:/, '');
const compressed = base45.decode(encoded);
const coseBuffer = pako.inflate(compressed);

// Leer clave pública EC en PEM
const pemRaw = fs.readFileSync('./clavePublica.pem', 'utf8');
const pem = PEM.parse(pemRaw)[0];

// Extraer coordenadas X e Y desde SubjectPublicKeyInfo
const pubKeyBytes = pem.body; // formato ASN.1 SubjectPublicKeyInfo
const pubKey = pubKeyBytes.slice(-65); // Últimos 65 bytes → 0x04 + X (32) + Y (32)

if (pubKey[0] !== 0x04) {
  throw new Error('Clave pública no está en formato sin comprimir (0x04).');
}

const x = Buffer.from(pubKey.slice(1, 33));
const y = Buffer.from(pubKey.slice(33, 65));

const verifier = {
  key: {
    x,
    y,
    crv: 'P-256',
    kty: 'EC'
  }
};

// Verificar firma
cose.sign.verify(coseBuffer, verifier)
  .then((payload) => {
    const decoded = cbor.decode(payload);
    console.log('✅ Verificación exitosa. Payload:');
    console.log(decoded);
  })
  .catch((err) => {
    console.error('❌ Firma inválida:', err);
  });
