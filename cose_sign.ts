import * as cose from 'cose-js';
import * as fs from 'fs';
import zlib from 'pako';
import * as cbor from 'cbor';
import { PrivateKey } from '@fidm/x509';
const base45 = require('base45-js');

interface CoseHeaders {
  p: { alg: string };
  u: Record<string, unknown>;
}

interface CoseSigner {
  key: {
    d: Buffer;
    crv: string;
    kty: string;
  };
}

function readPrivateKey(path: string): Buffer {
  const pem = fs.readFileSync(path); // Devuelve directamente un Buffer
  const pk = PrivateKey.fromPEM(pem);
  const d = Buffer.from(pk.keyRaw.subarray(7, 7 + 32));

  return Buffer.from(d);
}

function readJsonFromStdin(): Promise<any> {
  return new Promise((resolve, reject) => {
    let json = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (json += chunk));
    process.stdin.on('end', () => {
      try {
        resolve(JSON.parse(json));
      } catch (err) {
        reject(`❌ Error al parsear JSON: ${err}`);
      }
    });
    process.stdin.on('error', reject);
  });
}

async function main() {
  try {
    const keyD = readPrivateKey('./llavePrivada.p8');
    const data = await readJsonFromStdin();

    // Codificar en CBOR
    const plaintext = cbor.encode(data);

    const headers: CoseHeaders = {
      p: { alg: 'ES256' },
      u: {},
    };

    const signer: CoseSigner = {
      key: {
        d: keyD,
        crv: 'P-256',
        kty: 'EC',
      },
    };

    // Crear firma COSE
    const buf = await cose.sign.create(headers, plaintext, signer);

    // Comprimir y codificar como Base45 (como EU DGC)
    const deflated = zlib.deflate(buf);
    const encoded = 's6JzcMj5iQ:' + base45.encode(deflated);

    process.stdout.write(encoded);
  } catch (err) {
    console.error('❌ Error al firmar:', err);
  }
}

main();
