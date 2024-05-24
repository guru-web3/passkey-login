import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { NextRequest, NextResponse } from 'next/server';

import PasskeyRepository from '@/lib/passkey/passkeyRepository';

const passkeyRepo = new PasskeyRepository();
// CONSTANTS
const CHALLENGE_TTL = Number(process.env.WEBAUTHN_CHALLENGE_TTL) || 60_000;

export async function POST(req: NextRequest, _res: NextResponse) {
  const rpID = req.headers.get('origin') as string;
  const { challenge, challengeTimestamp } = createChallenge();
  const options = await generateAuthenticationOptions({
    userVerification: 'required',
    rpID: rpID,
    challenge,
  });

  await passkeyRepo.set(
    ['challenges', rpID, options.challenge],
    challengeTimestamp,
    {
      expireIn: CHALLENGE_TTL,
    }
  );
  return NextResponse.json({ options });
}

function createChallenge(): {
  challenge: Uint8Array;
  challengeTimestamp: string;
} {
  const challengeTimestampInMS = Date.now();
  const challengeTimestampInS = ~~(challengeTimestampInMS / 1000);
  const challengeTimestamp = challengeTimestampInS.toString();
  const challenge = Uint8Array.from(challengeTimestamp, (c) => c.charCodeAt(0));
  return { challenge, challengeTimestamp };
}
