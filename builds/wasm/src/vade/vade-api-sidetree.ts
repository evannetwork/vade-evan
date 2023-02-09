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
   * @param updateKey the JWK public key which will be used for the initial update key
   * @param recoveryKey the JWK public key which will be used for the initial recovery key
   * @param publicKeys an optional array of JWK keys which should be initially referenced in the did document
   * @param services an optional array of services which should be initially referenced in the did document
   * @param context current context
   */
  public async createDid(
    updateKey: JsonWebKeyWithNonce,
    recoveryKey: JsonWebKeyWithNonce,
    publicKeys?: PublicKeyModel[],
    services?: Service[],
  ): Promise<DidCreateResponse> {
    return this.executeVade<DidCreateOptions, DidCreatePayload, DidCreateResponse>({
      command: 'did_create',
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

  /**
   * Updates a sidetree did document with the defined patches
   * @param did full did as string
   * @param updateKey previous defined private JWK key in the did document
   * @param nextUpdateKey public JWK key which will be used for the next update
   * @param patches an array of defined patches which should be applied to the did document
   */
  public async updateDid(
    did: string,
    updateKey: JsonWebKeyWithNonce,
    nextUpdateKey: JsonWebKeyWithNonce,
    patches: Patch[],
  ): Promise<void> {
    await this.executeVade<DidUpdateOptions, DidUpdatePayload, void>({
      command: 'did_update',
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

  /**
   * deactivates a did (not recoverable anymore)
   * @param did full did as string
   * @param recoveryKey private JWK key which was defined as recovery key
   */
  public async deactivateDid(did: string, recoveryKey: JsonWebKeyWithNonce): Promise<void> {
    await this.executeVade<DidUpdateOptions, DidDeactivatePayload, void>({
      command: 'did_update',
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

  /**
   * recovers a did to a new state with the recovery key
   * @param did full did as string
   * @param updateKey previous defined private JWK key in the did document
   * @param recoveryKey previous defined private JWK key in the did document
   * @param nextUpdateKey public JWK key which will be used for the next update
   * @param nextRecoveryKey public JWK key which will be used for the next recovery
   * @param patches  an array of defined patches which should be applied to the did document
   */
  public async recoverDid(
    did: string,
    updateKey: JsonWebKeyWithNonce,
    recoveryKey: JsonWebKeyWithNonce,
    nextUpdateKey: JsonWebKeyWithNonce,
    nextRecoveryKey: JsonWebKeyWithNonce,
    patches: Patch[],
  ): Promise<void> {
    await this.executeVade<DidUpdateOptions, DidRecoverPayload, void>({
      command: 'did_update',
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
   */
  public async getDid(did: string): Promise<DIDDocument> {
    try {
      return await this.executeVade<void, void, DIDDocument>({
        command: 'did_resolve',
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
