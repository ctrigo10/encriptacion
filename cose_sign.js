const cose = require('cose-js');
const fs = require('fs');
const zlib = require('pako');
const cbor = require('cbor');
const base45 = require('base45-js');
const { PrivateKey } = require('@fidm/x509');

// Leer clave privada en formato PKCS#8
const pk = PrivateKey.fromPEM(fs.readFileSync('./llavePrivada.p8'));

// Obtener 'd' (clave privada) y coordenadas públicas 'x' y 'y'
const keyD = Buffer.from(pk.keyRaw.slice(7, 7 + 32)); // D

// Leer el JSON desde stdin
const buffer = Buffer.alloc(4096);
const len = fs.readSync(process.stdin.fd, buffer, 0, buffer.length);
const data = JSON.parse(buffer.slice(0, len));

// CBOR encode
const plaintext = cbor.encode(data);

// Headers COSE
const headers = {
  p: { alg: 'ES256' },
  u: {}
};

// Preparar firmante
const signer = {
  key: {
    d: keyD,
    crv: 'P-256',
    kty: 'EC'
  }
};

// Crear firma COSE
cose.sign.create(headers, plaintext, signer)
  .then((buf) => {
    // Comprimir y codificar como base45 (como EU DGC)
    const deflated = zlib.deflate(buf);
    const encoded = 's6JzcMj5iQ:' + base45.encode(deflated);
    process.stdout.write(Buffer.from(encoded).toString());
  }).catch((err) => {
    console.error('❌ Error al firmar:', err);
  });
