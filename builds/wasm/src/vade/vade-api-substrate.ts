/* eslint-disable import/no-extraneous-dependencies */
import type { DIDDocument } from './interfaces';
import { DidUpdateArguments as SubstrateDidUpdateOptions } from './typings/vade-evan-substrate';
import { IdentityArguments } from './typings/vade-evan-substrate/typings';
import { checkRequiredProperties, VadeOptions, VadeApiShared } from './vade-api-shared';

class VadeApiSubstrate extends VadeApiShared {
  /**
   * whitelists a specific evan did on substrate that this private key can create DIDs
   *
   * @param identity identity to whitelist
   * @param privateKey reference to private key to sign with
   */
  public async whitelistIdentity(
    identity: string,
    privateKey: string,
  ): Promise<void> {
    if (!identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }
    await this.executeVade<SubstrateDidUpdateOptions, string, void>(
      {
        command: 'did_update',
        did: identity,
        options: {
          privateKey,
          operation: 'whitelistIdentity',
          identity,
        },
      },
    );
  }

  public async updateDid(
    did: string,
    params: { didDocument: DIDDocument },
    options: VadeOptions,
  ): Promise<void> {
    checkRequiredProperties(
      params,
      ['didDocument'],
      'params',
    );
    checkRequiredProperties(
      options,
      ['identity', 'privateKey'],
      'options',
    );
    if (!options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }
    await this.executeVade<SubstrateDidUpdateOptions, DIDDocument, void>(
      {
        command: 'did_update',
        did,
        options: {
          identity: options.identity,
          operation: 'setDidDocument',
          privateKey: options.privateKey,
        },
        payload: params.didDocument,
      },
    );
  }

  /**
   * Fetches a DID document for a DID.
   *
   * @param did DID to resolve
   */
  public async getDid(did: string): Promise<DIDDocument> {
    return this.executeVade<void, void, DIDDocument>(
      {
        command: 'did_resolve',
        did,
      },
    );
  }

  /**
   * Creates a new DID.
   *
   * @param did DID to resolve
   */
  public async createDid(options: VadeOptions): Promise<void> {
    checkRequiredProperties(
      options,
      ['identity', 'privateKey'],
      'options',
    );
    if (!options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }
    return this.executeVade<IdentityArguments, void, void>(
      {
        command: 'did_create',
        method: 'did:evan',
        options: {
          identity: options.identity,
          privateKey: options.privateKey,
        },
      },
    );
  }
}

export {
  VadeApiSubstrate,
};
