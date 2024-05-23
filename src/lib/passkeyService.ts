/* eslint-disable no-useless-escape */
import {
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';
import {
  AuthenticationResponseJSON,
  AuthenticatorAttachment,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import { NodeDetailManager } from '@toruslabs/fetch-node-details';
import { post } from '@toruslabs/http-helpers';
import {
  type BUILD_ENV_TYPE,
  BUILD_ENV,
  OPENLOGIN_NETWORK_TYPE,
} from '@toruslabs/openlogin-utils';
import Torus, { TorusKey } from '@toruslabs/torus.js';
import log from 'loglevel';

import { PASSKEY_SVC_URL } from './constants';
import { LoginParams, PasskeyServiceEndpoints } from './interfaces';
export const getPasskeyEndpoints = (buildEnv: BUILD_ENV_TYPE) => {
  const baseUrl = PASSKEY_SVC_URL[buildEnv];
  return {
    register: {
      options: `${baseUrl}/api/v3/auth/passkey/fast/register/options`,
      verify: `${baseUrl}/api/v3/auth/passkey/fast/register/verify`,
    },
    authenticate: {
      options: `${baseUrl}/api/v3/auth/passkey/fast/authenticate/options`,
      verify: `${baseUrl}/api/v3/auth/passkey/fast/authenticate/verify`,
    },
    crud: {
      list: `${baseUrl}/api/v3/passkey/fast/list`,
    },
  };
};

export interface ILoginData {
  authenticationResponse: AuthenticationResponseJSON;
  data: {
    challenge: string;
    privateKey: string;
    sessionSignatures: string[];
    transports: AuthenticatorTransportFuture[];
    publicKey: string;
    idToken: string;
    metadata: string;
    verifierId: string;
  };
}

export default class PasskeyService {
  trackingId = '';

  web3authClientId: string;

  web3authNetwork: OPENLOGIN_NETWORK_TYPE;

  buildEnv: string = BUILD_ENV.PRODUCTION;

  endpoints: PasskeyServiceEndpoints;

  rpID: string;

  rpName: string;

  verifier: string;

  constructor(params: {
    web3authClientId: string;
    web3authNetwork: OPENLOGIN_NETWORK_TYPE;
    buildEnv: BUILD_ENV_TYPE;
    rpID: string;
    rpName: string;
    verifier: string;
  }) {
    this.web3authClientId = params.web3authClientId;
    this.endpoints = getPasskeyEndpoints(params.buildEnv);
    this.buildEnv = params.buildEnv;
    this.web3authNetwork = params.web3authNetwork;
    this.rpID = params.rpID;
    this.rpName = params.rpName;
    this.verifier = params.verifier;
  }

  padString(input: string) {
    const segmentLength = 4;
    const stringLength = input.length;
    const diff = stringLength % segmentLength;
    if (!diff) {
      return input;
    }
    let position = stringLength;
    let padLength = segmentLength - diff;
    const paddedStringLength = stringLength + padLength;
    const buffer = Buffer.alloc(paddedStringLength);
    buffer.write(input);
    while (padLength--) {
      buffer.write('=', position++);
    }
    return buffer.toString();
  }

  toBase64(base64url: any) {
    base64url = base64url.toString();
    return this.padString(base64url).replace(/\-/g, '+').replace(/_/g, '/');
  }

  fromBase64 = (base64: string) => {
    return base64.replace(/[=]/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  };

  convertToRegistrationResponse = (result: any) => ({
    ...result,
    id: this.fromBase64(result.id),
    rawId: this.fromBase64(result.rawId),
    response: {
      ...result.response,
      attestationObject: this.fromBase64(result.response.attestationObject),
      clientDataJSON: this.fromBase64(result.response.clientDataJSON),
    },
    clientExtensionResults: {},
    type: 'public-key',
  });
  async initiateRegistration(params: {
    oAuthVerifier: string;
    oAuthVerifierId: string;
    username: string;
    signatures: string[];
    passkeyToken?: string;
    authenticatorAttachment?: AuthenticatorAttachment;
  }): Promise<RegistrationResponseJSON> {
    const data = await this.getRegistrationOptions(params);
    data.options.challenge = this.toBase64(data.options.challenge);
    data.options.rp.id = 'localhost';
    data.options.user.id = 'testtemp';

    this.trackingId = data.trackingId;
    const verificationResponse = await startRegistration(data.options);
    return verificationResponse;
  }

  async registerPasskey(params: {
    verificationResponse: RegistrationResponseJSON;
    signatures: string[];
    passkeyToken?: string;
    data?: string;
  }) {
    const result = await this.verifyRegistration(
      params.verificationResponse,
      params.signatures,
      params.passkeyToken as string,
      params.data as string
    );
    return { response: params.verificationResponse, data: result };
  }

  convertToAuthenticationResponseJSON = (response: any) => ({
    ...response,
    id: this.fromBase64(response.id),
    rawId: this.fromBase64(response.rawId),
    response: {
      clientDataJSON: this.fromBase64(response.response.clientDataJSON),
      authenticatorData: this.fromBase64(response.response.authenticatorData),
      signature: this.fromBase64(response.response.signature),
    },
    clientExtensionResults: {},
    type: 'public-key',
  });
  async registerCredential(options = {}) {
    options = Object.assign(
      {
        challenge: new Uint8Array([1, 2, 3, 4]), // Example value
        authenticatorSelection: {
          requireResidentKey: false,
        },
        rp: {
          id: 'localhost',
          name: 'Selenium WebDriver Test',
        },
        // challenge: "MTcxNjQzNTQyMQ",
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        user: {
          name: 'name',
          displayName: 'displayName',
          id: Int8Array.from([1]),
        },
      },
      options
    );
    try {
      const credential = await navigator.credentials.create({
        publicKey: options as any,
      });
      await this.getCredential({
        id: credential?.id,
        transports: [],
        type: 'public-key',
      });
      console.log('createCredential', credential);
      return {
        status: 'OK',
        credential: {
          id: credential?.id,
          rawId: Array.from(new Uint8Array(credential?.id as any)),
          transports: (credential as any)?.response?.getTransports(),
        },
      };
    } catch (error: any) {
      return { status: error.toString() };
    }
  }

  async getCredential(credentials: any, options = {}) {
    options = {
      challenge: new Uint8Array([9, 0, 1, 2]), // Example value
      // allowCredentials: credentials,
      userVerification: 'preferred',
      allowCredentials: [
        {
          id: credentials.id,
          transports: credentials.transports,
          type: 'public-key',
        },
      ],
      rpId: 'localhost',
    };
    try {
      const attestation = await navigator.credentials.get({
        publicKey: options as any,
      });
      console.log('getCredential', attestation);
      return {
        status: 'OK',
        attestation: {
          userHandle: new Uint8Array((attestation as any).response.userHandle),
        },
      };
    } catch (error: any) {
      return { status: error.toString() };
    }
  }
  async loginUser(authenticatorId?: string): Promise<ILoginData | null> {
    const data = await this.getAuthenticationOptions(authenticatorId);
    const { options, trackingId } = data;
    const tempChallenge = options.challenge;
    options.challenge = 'MTcxNjQzNTQyMQ';

    this.trackingId = trackingId;
    console.log({ options });
    const verificationResponse = await startAuthentication(options);
    // const verificationResponse = await this.startAuthenticationLocal(options);
    console.log({ verificationResponse });
    const formattedResponse =
      this.convertToAuthenticationResponseJSON(verificationResponse);
    console.log({ formattedResponse });
    const result = await this.verifyAuthentication(formattedResponse);
    const loginParams = {
      verifier: this.verifier,
      verifierId: result.data?.verifier_id,
      idToken: verificationResponse.response.signature,
      extraVerifierParams: {
        signature: verificationResponse.response.signature,
        clientDataJSON: verificationResponse.response.clientDataJSON,
        authenticatorData: verificationResponse.response.authenticatorData,
        publicKey: result.data?.credential_public_key,
        challenge: result.data?.challenge_timestamp,
        rpId: 'localhost',
        rpOrigin: window.location.origin,
        credId: formattedResponse.id,
      },
    };
    // get passkey postbox key
    const { privateKey: passkeyPrivateKey, sessionSignatures } =
      await this.getPasskeyPostboxKey(loginParams as LoginParams);
    console.log({ passkeyPrivateKey });
    if (result && result.verified && result.data) {
      log.info('authentication response', verificationResponse);
      return {
        authenticationResponse: verificationResponse,
        data: {
          privateKey: passkeyPrivateKey,
          sessionSignatures: sessionSignatures,
          challenge: options.challenge,
          transports: result.data.transports,
          publicKey: result.data.credential_public_key,
          idToken: result.data.id_token,
          metadata: result.data.metadata,
          verifierId: result.data.verifier_id,
        },
      };
    }
    return null;
  }

  async getAllPasskeys({
    passkeyToken = '',
    signatures = [],
  }: {
    passkeyToken: string;
    signatures: string[];
  }) {
    try {
      const response = await post<{
        success: boolean;
        data: { passkeys: Record<string, string> };
      }>(
        this.endpoints.crud.list,
        {
          web3auth_client_id: this.web3authClientId,
          network: this.web3authNetwork,
          signatures,
        },
        {
          headers: {
            Authorization: `Bearer ${passkeyToken}`,
          },
        }
      );
      if (response.success) {
        return response.data.passkeys;
      }
      throw new Error('Error getting passkeys');
    } catch (error) {
      if (error instanceof Response) {
        const res = await error.json();
        throw new Error(
          `Error getting passkeys, reason: ${res.error || 'unknown'}`
        );
      }
      log.error('error getting passkeys', error);
      throw error;
    }
  }

  private async getRegistrationOptions({
    authenticatorAttachment,
    oAuthVerifier,
    oAuthVerifierId,
    signatures,
    username,
    passkeyToken,
  }: {
    oAuthVerifier: string;
    oAuthVerifierId: string;
    signatures: string[];
    username: string;
    passkeyToken?: string;
    authenticatorAttachment?: AuthenticatorAttachment;
  }) {
    try {
      const response = await post<{
        success: boolean;
        data: {
          options: PublicKeyCredentialCreationOptionsJSON;
          trackingId: string;
        };
      }>(this.endpoints.register.options, {
        web3auth_client_id: this.web3authClientId,
        verifier_id: oAuthVerifierId,
        verifier: oAuthVerifier,
        authenticator_attachment: authenticatorAttachment,
        rp: {
          name: this.rpName,
          id: this.rpID,
        },
        username,
        network: this.web3authNetwork,
        signatures,
      });
      if (response.success) {
        return response.data;
      }
      throw new Error('Error getting registration options');
    } catch (error) {
      if (error instanceof Response) {
        const res = await error.json();
        throw new Error(
          `Error getting registration options, reason: ${
            res.error || 'unknown'
          }`
        );
      }
      log.error('error getting registration options', error);
      throw error;
    }
  }

  private async verifyRegistration(
    verificationResponse: RegistrationResponseJSON,
    signatures: string[],
    token: string,
    metadata: string
  ) {
    if (!this.trackingId)
      throw new Error(
        'trackingId is required, please restart the process again.'
      );
    try {
      const response = await post<{
        verified: boolean;
        error?: string;
        data?: { challenge_timestamp: string; credential_public_key: string };
      }>(
        this.endpoints.register.verify,
        {
          web3auth_client_id: this.web3authClientId,
          tracking_id: this.trackingId,
          verification_data: verificationResponse,
          network: this.web3authNetwork,
          signatures,
          metadata,
        },
        {
          headers: {
            Authorization: `Bearer ${token || ''}`,
          },
        }
      );
      if (response.verified) {
        return response;
      }
      throw new Error(`Error verifying registration, error: ${response.error}`);
    } catch (error) {
      if (error instanceof Response) {
        const res = await error.json();
        throw new Error(
          `Error verifying registration, reason: ${res.error || 'unknown'}`
        );
      }
      log.error('error verifying registration', error);
      throw error;
    }
  }

  private async getAuthenticationOptions(authenticatorId?: string) {
    try {
      const response = await post<{
        success: boolean;
        data: {
          options: PublicKeyCredentialCreationOptionsJSON;
          trackingId: string;
        };
      }>(this.endpoints.authenticate.options, {
        web3auth_client_id: this.web3authClientId,
        rp_id: this.rpID,
        // authenticator_id: authenticatorId,
        network: this.web3authNetwork,
      });
      if (response.success) {
        return response.data;
      }
      throw new Error('Error getting authentication options');
    } catch (error) {
      if (error instanceof Response) {
        const res = await error.json();
        throw new Error(
          `Error getting authentication options, reason: ${
            res.error || 'unknown'
          }`
        );
      }
      log.error('error getting authentication options', error);
      throw error;
    }
  }

  private async verifyAuthentication(
    verificationResponse: AuthenticationResponseJSON
  ) {
    if (!verificationResponse)
      throw new Error('verificationResponse is required.');
    try {
      const response = await post<{
        verified: boolean;
        data?: {
          challenge_timestamp: string;
          transports: AuthenticatorTransportFuture[];
          credential_public_key: string;
          rpID: string;
          id_token: string;
          metadata: string;
          verifier_id: string;
        };
        error?: string;
      }>(this.endpoints.authenticate.verify, {
        web3auth_client_id: this.web3authClientId,
        tracking_id: this.trackingId,
        verification_data: verificationResponse,
        network: this.web3authNetwork,
      });
      if (response.verified) {
        return { data: response.data, verified: response.verified };
      }
      throw new Error(
        `Error verifying authentication, error: ${response.error}`
      );
    } catch (error: unknown) {
      if (error instanceof Response) {
        const res = await error.json();
        throw new Error(
          `Error verifying authentication, reason: ${res.error || 'unknown'}`
        );
      }
      log.error('error verifying authentication', error);
      throw error;
    }
  }

  private getSessionSignatures(sessionData: TorusKey['sessionData']): string[] {
    return sessionData.sessionTokenData
      .filter((i) => Boolean(i))
      .map((session) =>
        JSON.stringify({ data: session.token, sig: session.signature })
      );
  }

  private async getPasskeyPostboxKey(loginParams: LoginParams) {
    const clientId = this.web3authClientId;
    const web3AuthNetwork = this.web3authNetwork;
    const nodeDetailManagerInstance = new NodeDetailManager({
      network: web3AuthNetwork,
    });

    const authInstance = new Torus({
      clientId,
      enableOneKey: true,
      network: web3AuthNetwork,
    });

    const { verifier, verifierId, idToken } = loginParams;
    const verifierDetails = { verifier, verifierId };

    const { torusNodeEndpoints, torusIndexes } =
      await nodeDetailManagerInstance.getNodeDetails(verifierDetails);

    const finalIdToken = idToken;
    const finalVerifierParams = { verifier_id: verifierId };

    const retrieveSharesResponse = await authInstance.retrieveShares(
      torusNodeEndpoints,
      torusIndexes,
      verifier,
      finalVerifierParams,
      finalIdToken,
      loginParams.extraVerifierParams || {}
    );

    if (!retrieveSharesResponse.finalKeyData.privKey)
      throw new Error('Unable to get passkey privkey.');
    return {
      privateKey: retrieveSharesResponse.finalKeyData.privKey.padStart(64, '0'),
      sessionSignatures: this.getSessionSignatures(
        retrieveSharesResponse.sessionData
      ),
    };
  }
}
