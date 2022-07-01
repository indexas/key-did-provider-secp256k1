import type {
    AuthParams,
    CreateJWSParams,
    GeneralJWS,
    DecryptJWEParams,
} from "dids";

import { RPCConnection } from "rpc-utils";
  
export declare type AuthSig = {
    sig: string;
    derivedVia: string;
    signedMessage: string;
    address: string;
};

export declare type LitActionParams = {
    conditions: Array<Object>;
    authSig: AuthSig;
    chain: string;
};

export interface ContextWithLit {
    did: string
    jsParams: LitActionParams
}

/**
 * @deprecated Signers will be expected to return base64url `string` signatures.
 */
 export interface EcdsaSignature {
    r: string
    s: string
    recoveryParam?: number | null
}

export interface JWSCreationOptions {
    canonicalize?: boolean
}

export declare type DIDProviderMethodsWithLit = {
    did_authenticate: {
        params: AuthParams;
        result: GeneralJWS;
    };
    did_createJWS: {
        params: CreateJWSParams;
        result: {
        jws: GeneralJWS;
    };
    };
    did_decryptJWE: {
        params: DecryptJWEParams;
        result: {
            cleartext: string;
        };
    };
};

export declare type DIDMethodNameWithLit = keyof DIDProviderMethodsWithLit;

export declare type DIDProviderWithLit = RPCConnection<DIDProviderMethodsWithLit>;
  

