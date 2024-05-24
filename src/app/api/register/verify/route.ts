import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { NextRequest, NextResponse } from 'next/server';

import { getrpID } from '@/lib/helper';
import PasskeyRepository from '@/lib/passkey/passkeyRepository';

const passkeyRepo = new PasskeyRepository();

export async function POST(req: NextRequest, _res: NextResponse) {
  const { username, cred, userId } = await req.json();

  const pubKey = cred.response.publicKey as string;

  // const userId = await getSignedCookie(req as any, SECRET, "userId")
  if (!userId) return new Response('UserId not found', { status: 401 });

  const clientData = JSON.parse(atob(cred.response.clientDataJSON));

  const rpID = req.headers.get('origin') as string;

  const verification = await verifyRegistrationResponse({
    response: cred,
    expectedChallenge: clientData.challenge,
    expectedRPID: getrpID(req.headers.get('origin') as string),
    expectedOrigin: rpID,
    requireUserVerification: true,
  });

  if (verification.verified) {
    const { credentialID, credentialPublicKey, counter } =
      verification.registrationInfo!;

    await passkeyRepo.createUser({
      userId,
      username,
    });
    const publicKey = isoBase64URL.fromBuffer(credentialPublicKey);
    await passkeyRepo.createCredential({
      userId,
      credentialId: credentialID,
      publicKey: pubKey,
      counter,
      credentialPublicKey: publicKey,
    });

    return NextResponse.json(verification);
  }
  return NextResponse.json('Unauthorized', { status: 401 });
}
