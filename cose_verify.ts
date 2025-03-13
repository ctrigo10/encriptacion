import * as cose from 'cose-js';
import * as fs from 'fs';
import pako from 'pako';
import * as cbor from 'cbor';
import { PEM } from '@fidm/asn1';
const base45 = require('base45-js');

// Leer mensaje firmado desde stdin
const buffer = Buffer.alloc(4096);
const len = fs.readSync(process.stdin.fd, buffer);
const input = buffer.subarray(0, len).toString().trim();

// Quitar prefijo y decodificar
const encoded = input.replace(/^s6JzcMj5iQ:/, '');
const compressed = base45.decode(encoded);
const coseBuffer = pako.inflate(compressed);

// Leer clave pública en formato PEM
const pemRaw = fs.readFileSync('./clavePublica.pem', 'utf8');
const pemParsed = PEM.parse(Buffer.from(pemRaw))[0];

// Extraer coordenadas X e Y desde la clave pública sin comprimir
const pubKeyBytes = pemParsed.body;
const pubKey = pubKeyBytes.subarray(pubKeyBytes.length - 65); // Últimos 65 bytes = 0x04 + X + Y

if (pubKey[0] !== 0x04) {
  throw new Error(
    'Clave pública no está en formato sin comprimir (esperado 0x04).'
  );
}

const x = Buffer.from(pubKey.subarray(1, 33));
const y = Buffer.from(pubKey.subarray(33, 65));

// Preparar verificador COSE
const verifier = {
  key: {
    x,
    y,
    crv: 'P-256',
    kty: 'EC',
  },
};

// Verificar firma
cose.sign
  .verify(coseBuffer, verifier)
  .then((payload: Buffer) => {
    const decoded = cbor.decode(payload);
    console.log('✅ Verificación exitosa. Payload:');
    console.log(decoded);
  })
  .catch((err: Error) => {
    console.error('❌ Firma inválida:', err);
  });
