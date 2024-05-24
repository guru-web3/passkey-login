import { knexRead, knexWrite } from '../database/knex';
import { redisClient } from '../db';

export interface IPasskeysRecord {
  web3auth_client_id: string;
  public_address: string;
  passkey_user_id: string;
  public_key: string;
  pubKey: string;
  verifier: string;
  verifier_id: string;
  factor: string;
  metadata: string;
  network: string;

  credential_id: string;
  credential_public_key: string;
  counter: number;
  credential_device_type: string;
  credential_backed_up: boolean;
  transports: string;
  user_verified: boolean;
  rp_id: string;

  origin: string;
  browser: string;
  browser_version: string;
  os: string;
  os_version: string;
  platform: string;
  user_ip_address: string;
  created_at: Date;
  updated_at: Date;
}

class PasskeyRepository {
  static passkeyRepository: PasskeyRepository;

  constructor() {
    if (PasskeyRepository.passkeyRepository) {
      return PasskeyRepository.passkeyRepository;
    }
    PasskeyRepository.passkeyRepository = this;
  }

  async set(
    key: (string | number)[],
    value: any,
    options?: { expireIn?: number; overwrite?: boolean }
  ) {
    const serializedKey = JSON.stringify(key);
    const valueToStore = JSON.stringify(value);
    const { expireIn, overwrite } = options || {};

    const exists = await redisClient.exists(serializedKey);
    if (exists && !overwrite) {
      throw new Error('Key already exists');
    }

    if (expireIn !== undefined) {
      await redisClient.setex(serializedKey, expireIn, valueToStore);
    } else {
      await redisClient.set(serializedKey, valueToStore);
    }
  }

  async get<T>(key: (string | number)[]): Promise<T | null> {
    const value = await redisClient.get(JSON.stringify(key));
    return value ? (JSON.parse(value) as T) : null;
  }

  async delete(key: (string | number)[]) {
    await redisClient.del(JSON.stringify(key));
  }

  async createUser(user: { userId: string; username: string }) {
    // const isValidUUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(user.userId);
    // if (!isValidUUID) {
    //     throw new Error("Invalid UUID format for userId");
    // }

    try {
      await knexWrite('global_wallet_passkey_users').insert({
        passkey_user_id: user.userId,
        username: user.username,
      });
    } catch (error) {
      console.error('Error creating user:', error);
      throw error;
    }
  }

  async getPasskeyUserById(userId: string) {
    try {
      const user = await knexRead('global_wallet_passkey_users')
        .where({ passkey_user_id: userId })
        .first();
      return user;
    } catch (error) {
      console.error('Error retrieving user:', error);
      return null;
    }
  }

  async createCredential(credential: {
    credentialId: string;
    userId: string;
    credentialPublicKey: string;
    counter: number;
    publicKey: string;
  }) {
    try {
      await knexWrite<IPasskeysRecord>(
        'global_wallet_passkey_credentials'
      ).insert({
        credential_id: credential.credentialId,
        passkey_user_id: credential.userId,
        public_key: credential.credentialPublicKey,
        pubKey: credential.publicKey,
      });
    } catch (error) {
      console.error('Error creating credential:', error);
      throw error;
    }
  }

  async getCredentialById(credentialId: string) {
    try {
      const credential = await knexRead('global_wallet_passkey_credentials')
        .where({ credential_id: credentialId })
        .first();
      return credential;
    } catch (error) {
      return null;
    }
  }

  async getCredentialsByUserId(userId: string) {
    try {
      const credentials = await knexRead(
        'global_wallet_passkey_credentials'
      ).where({ passkey_user_id: userId });
      return credentials;
    } catch (error) {
      console.error('Error retrieving credentials:', error);
      return [];
    }
  }

  async updateCredentialCounter(credentialId: string, newCounter: number) {
    try {
      await knexWrite<IPasskeysRecord>('global_wallet_passkey_credentials')
        .where({ credential_id: credentialId })
        .update({ counter: newCounter as number });
    } catch (error) {
      console.error('Error updating credential counter:', error);
      throw error;
    }
  }
}

export default PasskeyRepository;
