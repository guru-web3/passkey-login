import { generateRegistrationOptions } from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';
import { NextRequest, NextResponse } from 'next/server';
import { v4 as uuidv4 } from 'uuid';

import PasskeyRepository from '@/lib/passkey/passkeyRepository';

const passkeyRepo = new PasskeyRepository();
// CONSTANTS
const CHALLENGE_TTL = Number(process.env.WEBAUTHN_CHALLENGE_TTL) || 60_000;

export async function POST(req: NextRequest) {
  const { username } = await req.json();

  const userID = uuidv4();

  const rpID = req.headers.get('origin');
  const options = await generateRegistrationOptions({
    rpName: rpID as string,
    rpID: rpID as string,
    userID: isoUint8Array.fromUTF8String(userID),
    userName: username,
    userDisplayName: username,
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
  });

  passkeyRepo.set(['challenges', rpID as string, options.challenge], true, {
    expireIn: CHALLENGE_TTL,
  });

  return NextResponse.json({ options });
}
