import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { Base64URLString } from '@simplewebauthn/types';
import base64url from 'base64url';
import { keccak256 } from 'ethereum-cryptography/keccak';
import { NextRequest, NextResponse } from 'next/server';

import { base64urlToUint8Array, getrpID } from '@/lib/helper';
import PasskeyRepository from '@/lib/passkey/passkeyRepository';

export type Credential = {
  pubKey?: string;
  credentialID: Base64URLString; // serialize to handle Uint8Array in Redis
  credentialPublicKey: Base64URLString; // serialize to handle Uint8Array in Redis
  counter: number;
};
export type Challenge = boolean;

const passkeyRepo = new PasskeyRepository();

export async function POST(req: NextRequest) {
  const { userId, cred } = await req.json();

  const clientData = JSON.parse(atob(cred.response.clientDataJSON));

  const clientDataJSON = atob(cred.response.clientDataJSON);
  if (typeof clientDataJSON !== 'string') {
    throw new Error('clientDataJSON must be a string');
  }

  const credential = await passkeyRepo.getCredentialById(cred.id);
  const user = await passkeyRepo.getPasskeyUserById(
    credential?.passkey_user_id as string
  );
  const rpID = req.headers.get('origin');

  if (!user) return NextResponse.json('Unauthorized', { status: 401 });
  if (!credential) return NextResponse.json('Unauthorized', { status: 401 });

  const challengeTimeStamp = await passkeyRepo.get<Challenge>([
    'challenges',
    rpID,
    clientData.challenge,
  ]);
  if (!challengeTimeStamp) {
    return NextResponse.json('Unauthorized', { status: 401 });
  }

  // Convert from Base64url to Uint8Array
  const credentialID = base64urlToUint8Array(
    credential.credential_id as string
  );
  const credentialPublicKey = base64urlToUint8Array(
    credential.public_key as string
  );

  const options = {
    response: cred,
    expectedChallenge: clientData.challenge,
    expectedOrigin: req.headers.get('origin'), //! Allow from any origin
    expectedRPID: getrpID(req.headers.get('origin') as string),
    authenticator: {
      ...credential,
      credentialID: credentialID as Uint8Array,
      credentialPublicKey: credentialPublicKey,
    },
  };
  const verification = await verifyAuthenticationResponse(options as any);

  if (verification.verified) {
    const { newCounter } = verification.authenticationInfo;

    await passkeyRepo.delete(['challenges', clientData.challenge]);

    await passkeyRepo.updateCredentialCounter(cred.id, newCounter);

    return NextResponse.json({
      verified: verification.verified,
      data: {
        credential_public_key: credential.public_key,
        verifier_id: base64url.fromBase64(
          Buffer.from(
            keccak256(Buffer.from(credential.public_key, 'base64'))
          ).toString('base64')
        ),
        challenge_timestamp: challengeTimeStamp,
        signature: cred.response.signature,
        metadata: credential.metadata,
      },
      pubkey: credential.pubKey,
      userId,
    });
  }
  return NextResponse.json('Unauthorized', { status: 401 });
  //     return NextResponse.json(verification);
  // }
  // return NextResponse.json("Unauthorized", {status: 401});
  // // return c.text("Unauthorized", 401)
}
