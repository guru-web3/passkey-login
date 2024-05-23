import { NamedAlgo } from './types';
import {
  concatenateBuffers,
  parseBase64url,
  sha256,
  toBase64url,
} from './utils';

export async function verifySignature({
  algorithm,
  publicKey,
  authenticatorData,
  clientData,
  signature,
  verbose,
}: any): Promise<boolean> {
  const algoParams = getAlgoParams(algorithm);
  const cryptoKey = await parseCryptoKey(algoParams, publicKey);

  if (verbose) {
    console.debug(cryptoKey);
  }

  const clientHash = await sha256(parseBase64url(clientData));

  // during "login", the authenticatorData is exactly 37 bytes
  const comboBuffer = concatenateBuffers(
    parseBase64url(authenticatorData),
    clientHash
  );

  if (verbose) {
    console.debug('Crypto Algo: ' + JSON.stringify(algoParams));
    console.debug('Public key: ' + publicKey);
    console.debug('Data: ' + toBase64url(comboBuffer));
    console.debug('Signature: ' + signature);
  }

  // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
  let signatureBuffer = parseBase64url(signature);
  if (algorithm == 'ES256') signatureBuffer = convertASN1toRaw(signatureBuffer);
  console.log('fromAsn1DERtoRSSignature', fromAsn1DERtoRSSignature(signature));

  const isValid = await crypto.subtle.verify(
    algoParams,
    cryptoKey,
    signatureBuffer,
    comboBuffer
  );
  // const tsignature = await crypto.subtle.sign(algoParams, cryptoKey, comboBuffer)

  console.log({ isValid });
  return isValid;
}

// Function to derive a stable entropy value from the initial signature
async function deriveEntropy(r1Signature: string) {
  // Decode the base64 r1 signature
  const r1Buffer = Buffer.from(r1Signature, 'base64');

  // Create a hash of the r1 signature
  const hash = crypto.createHash('sha256');
  hash.update(r1Buffer);

  // Get the digest as a hex string
  const entropy = hash.digest('hex');

  return entropy;
}
// async function deriveEntropy(signature: string) {
//     const hashBuffer = await crypto.subtle.digest("SHA-256", new Uint8Array(signature as any));
//     const hashArray = Array.from(new Uint8Array(hashBuffer));
//     console.log("bello", hashArray.map(b => b.toString(16).padStart(2, "0")).join(""))
//   }

export enum COSEAlgorithm {
  ES256 = -7,
  ES384 = -35,
  ES512 = -36,
  // RS256 = -257,
  // RS384 = -258,
  // RS512 = -259,
}

export const COSEAlgToDigestBits = {
  [COSEAlgorithm.ES256.toString()]: 256,
  [COSEAlgorithm.ES384.toString()]: 384,
  [COSEAlgorithm.ES512.toString()]: 512,
};
export function fromAsn1DERtoRSSignature(
  signature: string,
  hashBitLength: number = COSEAlgToDigestBits[COSEAlgorithm.ES256.toString()]
) {
  const signatureBuffer = Buffer.from(signature, 'utf8');
  console.log({ hashBitLength });
  if (hashBitLength % 8 !== 0) {
    throw new Error(`hashBitLength ${hashBitLength} is not a multiple of 8`);
  }

  const sig = new Uint8Array(signatureBuffer);

  console.log({ signatureBuffer }, { sig: sig[0] }, { signature });
  // if (sig[0] != 48) {
  //     throw new Error('Invalid ASN.1 DER signature');
  // }

  const rStart = 4;
  const rLength = sig[3];
  const sStart = rStart + rLength + 2;
  const sLength = sig[rStart + rLength + 1];

  let r = sig.slice(rStart, rStart + rLength);
  let s = sig.slice(sStart, sStart + sLength);

  // Remove any 0 padding
  for (const i of r.slice()) {
    if (i !== 0) {
      break;
    }
    r = r.slice(1);
  }
  for (const i of s.slice()) {
    if (i !== 0) {
      break;
    }
    s = s.slice(1);
  }

  const padding = hashBitLength / 8;

  console.log({ r }, { s });
  if (r.length > padding || s.length > padding) {
    throw new Error(
      `Invalid r or s value bigger than allowed max size of ${padding}`
    );
  }

  const rPadding = padding - r.length;
  const sPadding = padding - s.length;

  return concatBuffer(
    new Uint8Array(rPadding).fill(0),
    r,
    new Uint8Array(sPadding).fill(0),
    s
  );
}
export function concatBuffer(...buffers: ArrayBuffer[]) {
  const length = buffers.reduce((acc, b) => acc + b.byteLength, 0);
  const tmp = new Uint8Array(length);

  let prev = 0;
  for (const buffer of buffers) {
    tmp.set(new Uint8Array(buffer), prev);
    prev += buffer.byteLength;
  }

  return tmp.buffer;
}

function convertASN1toRaw(signatureBuffer: ArrayBuffer) {
  // Convert signature from ASN.1 sequence to "raw" format
  const usignature = new Uint8Array(signatureBuffer);
  const rStart = usignature[4] === 0 ? 5 : 4;
  const rEnd = rStart + 32;
  const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
  const r = usignature.slice(rStart, rEnd);
  const s = usignature.slice(sStart);
  console.log({ r }, { s });
  return new Uint8Array([...r, ...s]);
}

function getAlgoParams(algorithm: NamedAlgo): any {
  switch (algorithm) {
    case 'RS256':
      return {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      };
    case 'ES256':
      return {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
      };
    // case 'EdDSA': Not supported by browsers
    default:
      throw new Error(
        `Unknown or unsupported crypto algorithm: ${algorithm}. Only 'RS256' and 'ES256' are supported.`
      );
  }
}

type AlgoParams =
  | AlgorithmIdentifier
  | RsaHashedImportParams
  | EcKeyImportParams
  | HmacImportParams
  | AesKeyAlgorithm;

async function parseCryptoKey(
  algoParams: AlgoParams,
  publicKey: string
): Promise<CryptoKey> {
  const buffer = parseBase64url(publicKey);
  return crypto.subtle.importKey('spki', buffer, algoParams, false, ['verify']);
}

// verifySignature({
//     algorithm: 'ES256',
//     publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER2nh9GWV-_qQaoQYt7rsUiYTK9a6BD_dCU6esafhCvHofpZEOLCInPzURDBPTsUrfz6wbaVgoEZ6z_E1xqB9_g==',
//     authenticatorData: "T7IIVvJKaufa_CeBCQrIR3rm4r0HJmAjbMYUxvt8LqAdAAAAAA==",
//     clientData: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNTYzYmRiODgtMGNkYy00NzcwLTg0YWItMzliZGZjNDA3MTNiIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5wYXNzd29yZGxlc3MuaWQiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
//     signature: "MEUCIGxNuowyyaAXc5KEwCkQcZgpihPKhN7tkNipn65wSVMWAiEA9oki5U5ymYc8yF7FqF-CSZ2yguutShN0iZfuZM4eFP4=",
//     verbose: true,
// })

console.log(
  deriveEntropy(
    'MEQCIE2wUhk_Euod2o4tOnkm39Ec_KhVWzU3voiX9GySCLWsAiBXqi3hRITLef4dClBoKmPwK-tA3YI2yQtlMsBz-4A4kQ=='
  )
);
