import type { DIDDocument } from './interfaces';
import {
  DidCreateOptions,
  DidCreatePayload,
  DidCreateResponse,
  DidDeactivatePayload,
  DidRecoverPayload,
  DidUpdateOptions,
  DidUpdatePayload,
  JsonWebKeyWithNonce,
  Patch,
  PublicKeyModel,
  Service,
} from './typings/vade-sidetree';

import { VadeApiShared } from './vade-api-shared';

export enum UpdateType {
  Update = 'update',
  Recovery = 'recovery',
  Deactivate = 'deactivate',
}

export enum PublicKeyPurpose {
  Authentication = 'authentication',
  AssertionMethod = 'assertionMethod',
  CapabilityInvocation = 'capabilityInvocation',
  CapabilityDelegation = 'capabilityDelegation',
  KeyAgreement = 'keyAgreement',
}

const TYPE_SIDETREE = 'sidetree';
class VadeApiSidetree extends VadeApiShared {
  /**
   * create sidetree DID document
   *
   * @param updateKey
   * @param recoveryKey
   * @param publicKeys
   * @param services
   * @param context current context
   */
  public async createDid(
    updateKey: JsonWebKeyWithNonce,
    recoveryKey: JsonWebKeyWithNonce,
    publicKeys?: PublicKeyModel[],
    services?: Service[],
  ): Promise<DidCreateResponse> {
    return this.executeVade<DidCreateOptions, DidCreatePayload, DidCreateResponse>({
      command: 'did',
      subcommand: 'create',
      method: 'did:evan',
      options: {
        type: TYPE_SIDETREE,
        waitForCompletion: true,
      },
      payload: {
        recoveryKey,
        updateKey,
        publicKeys,
        services,
      },
    });
  }

  public async updateDid(
    did: string,
    updateKey: JsonWebKeyWithNonce,
    nextUpdateKey: JsonWebKeyWithNonce,
    patches: Patch[],
  ): Promise<void> {
    await this.executeVade<DidUpdateOptions, DidUpdatePayload, void>({
      command: 'did',
      subcommand: 'update',
      method: null,
      options: {
        type: TYPE_SIDETREE,
        waitForCompletion: true,
      },
      payload: {
        updateType: UpdateType.Update,
        updateKey,
        nextUpdateKey,
        patches,
      },
      did,
    });
  }

  public async deactivateDid(did: string, recoveryKey: JsonWebKeyWithNonce): Promise<void> {
    await this.executeVade<DidUpdateOptions, DidDeactivatePayload, void>({
      command: 'did',
      subcommand: 'update',
      method: null,
      options: {
        type: TYPE_SIDETREE,
        waitForCompletion: true,
      },
      payload: {
        updateType: UpdateType.Deactivate,
        recoveryKey,
      },
      did,
    });
  }

  public async recoverDid(
    did: string,
    updateKey: JsonWebKeyWithNonce,
    recoveryKey: JsonWebKeyWithNonce,
    nextUpdateKey: JsonWebKeyWithNonce,
    nextRecoveryKey: JsonWebKeyWithNonce,
    patches: Patch[],
  ): Promise<void> {
    await this.executeVade<DidUpdateOptions, DidRecoverPayload, void>({
      command: 'did',
      subcommand: 'update',
      method: null,
      options: {
        type: TYPE_SIDETREE,
        waitForCompletion: true,
      },
      payload: {
        updateType: UpdateType.Recovery,
        updateKey,
        nextUpdateKey,
        nextRecoveryKey,
        recoveryKey,
        patches,
      },
      did,
    });
  }

  /**
   * Fetches a DID document for a DID.
   *
   * @param did DID to resolve
   * @param context current context
   */
  public async getDid(did: string): Promise<DIDDocument> {
    try {
      return await this.executeVade<void, void, DIDDocument>({
        command: 'did',
        subcommand: 'resolve',
        method: '',
        did,
      });
    } catch (e) {
      throw new Error(e);
    }
  }
}

export {
  VadeApiSidetree,
};
