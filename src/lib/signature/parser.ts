import { authenticatorMetadata } from './constant.js';
import {
  AuthenticationEncoded,
  AuthenticationParsed,
  AuthenticatorInfo,
  ClientInfo,
  RegistrationEncoded,
  RegistrationParsed,
} from './types';
import * as utils from './utils.js';

const utf8Decoder = new TextDecoder('utf-8');

export function parseClient(data: string | ArrayBuffer): ClientInfo {
  if (typeof data == 'string') data = utils.parseBase64url(data);
  return JSON.parse(utf8Decoder.decode(data));
}

export function parseAuthenticator(
  data: string | ArrayBuffer
): AuthenticatorInfo {
  if (typeof data == 'string') data = utils.parseBase64url(data);
  return parseAuthBuffer(data);
}

export function parseAttestation(data: string | ArrayBuffer): unknown {
  //if(typeof data == 'string')
  //    data = utils.parseBase64url(data)
  // Useless comment, let's at least provide the raw value
  // return "The device attestation proves the authenticity of the device model / aaguid. It's not guaranteed to be included and really complex to parse / verify. Good luck with that one!"
  return data;
}

export function parseRegistration(
  registration: RegistrationEncoded
): RegistrationParsed {
  return {
    username: registration.username,
    credential: registration.credential,

    client: parseClient(registration.clientData),
    authenticator: parseAuthenticator(registration.authenticatorData),
    attestation: registration.attestationData
      ? parseAttestation(registration.attestationData)
      : null,
  };
}

export function parseAuthentication(
  authentication: AuthenticationEncoded
): AuthenticationParsed {
  return {
    credentialId: authentication.credentialId,
    client: parseClient(authentication.clientData),
    authenticator: parseAuthenticator(authentication.authenticatorData),
    signature: authentication.signature,
  };
}

export function parseAuthBuffer(authData: ArrayBuffer) {
  //console.debug(authData)
  const flags = new DataView(authData.slice(32, 33)).getUint8(0);
  //console.debug(flags)

  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  let parsed: any = {
    rpIdHash: utils.toBase64url(authData.slice(0, 32)),
    flags: {
      userPresent: !!(flags & 1),
      //reserved1: !!(flags & 2),
      userVerified: !!(flags & 4),
      backupEligibility: !!(flags & 8),
      backupState: !!(flags & 16),
      //reserved2: !!(flags & 32),
      attestedData: !!(flags & 64),
      extensionsIncluded: !!(flags & 128),
    },
    counter: new DataView(authData.slice(33, 37)).getUint32(0, false), // Big-Endian!
  };

  // this is more descriptive than "backupState"
  parsed.synced = parsed.flags.backupState;

  if (authData.byteLength > 37) {
    // registration contains additional data

    const aaguid = extractAaguid(authData); // bytes 37->53
    // https://w3c.github.io/webauthn/#attested-credential-data
    parsed = {
      ...parsed,
      aaguid,
      name: authenticatorMetadata[aaguid] ?? 'Unknown',
      icon_light:
        'https://webauthn.passwordless.id/authenticators/' +
        aaguid +
        '-light.png',
      icon_dark:
        'https://webauthn.passwordless.id/authenticators/' +
        aaguid +
        '-dark.png',
    };
  }

  return parsed;
}

export function extractAaguid(authData: ArrayBuffer): string {
  return formatAaguid(authData.slice(37, 53)); // 16 bytes
}

function formatAaguid(buffer: ArrayBuffer): string {
  let aaguid = utils.bufferToHex(buffer);
  aaguid =
    aaguid.substring(0, 8) +
    '-' +
    aaguid.substring(8, 12) +
    '-' +
    aaguid.substring(12, 16) +
    '-' +
    aaguid.substring(16, 20) +
    '-' +
    aaguid.substring(20, 32);
  return aaguid; // example: "d41f5a69-b817-4144-a13c-9ebd6d9254d6"
}
