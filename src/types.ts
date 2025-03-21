export interface ResponseAddress {
  pubkey: Buffer
  address: string
}

export interface ResponseSign {
  signature: Buffer
}

export interface StdSigData {
    data: string;
    signer: Uint8Array;
    domain: string;
    authenticationData: Uint8Array;
    requestId?: string;
    hdPath?: string;
    signature?: Uint8Array;
}

export interface StdSigDataResponse extends StdSigData {
    signature: Uint8Array;
}

export enum ScopeType {
    UNKNOWN = -1,
    AUTH = 1
}

export interface StdSignMetadata {
    scope: ScopeType;
    encoding: string;
}