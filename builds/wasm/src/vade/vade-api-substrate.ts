/* eslint-disable import/no-extraneous-dependencies */
import type { DIDDocument } from './interfaces';
import { DidUpdateArguments as SubstrateDidUpdateOptions, IdentityArguments } from './typings/vade-evan-substrate';
import { checkRequiredProperties, VadeOptions, VadeApiShared } from './vade-api-shared';

const TYPE_SUBSTRATE = 'substrate';

class VadeApiSubstrate extends VadeApiShared {
  /**
   * whitelists a specific evan did on substrate that this private key can create DIDs
   *
   * @param identity identity to whitelist
   * @param signingKeyUuid reference to private key to sign with
   * @param remoteSignerUrl
   */
  public async whitelistIdentity(
    identity: string,
    signingKeyUuid: string,
    remoteSignerUrl: string,
  ): Promise<void> {
    if (!identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }
    await this.executeVade<SubstrateDidUpdateOptions, string, void>(
      {
        command: 'did',
        subcommand: 'update',
        method: null,
        options: {
          signingKey: remoteSignerUrl ? identity : signingKeyUuid,
          operation: 'whitelistIdentity',
          identity,
          type: TYPE_SUBSTRATE,
        },
        payload: 'no_payload',
        did: identity,
        signer: remoteSignerUrl ? `remote|${remoteSignerUrl}` : undefined,
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
      ['identity', 'signingKey'],
      'options',
    );
    if (!options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }
    await this.executeVade<SubstrateDidUpdateOptions, DIDDocument, void>(
      {
        command: 'did',
        subcommand: 'update',
        options: {
          identity: options.identity,
          operation: 'setDidDocument',
          signingKey: options.remoteSignerUrl ? options.identity : options.signingKey,
          type: TYPE_SUBSTRATE,
        },
        payload: params.didDocument,
        did: options.identity,
        signer: options.remoteSignerUrl ? `remote|${options.remoteSignerUrl}` : undefined,
        method: null,
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
        command: 'did',
        subcommand: 'resolve',
        method: '',
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
      ['identity', 'signingKey'],
      'options',
    );
    if (!options.identity.startsWith('did')) {
      throw new Error('identity should start with did:evan:...');
    }
    return this.executeVade<IdentityArguments, void, void>(
      {
        command: 'did',
        subcommand: 'create',
        method: 'did:evan',
        options: {
          identity: options.identity,
          signingKey: options.signingKey,
          type: TYPE_SUBSTRATE,
        },
      },
    );
  }
}

export {
  VadeApiSubstrate,
};
