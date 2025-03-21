/** ******************************************************************************
 *  (c) 2019-2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */
import type Transport from '@ledgerhq/hw-transport'
import BaseApp, {BIP32Path, ERROR_DESCRIPTION_OVERRIDE, INSGeneric, LedgerError, processErrorResponse, processResponse, ResponsePayload, ResponseVersion} from '@zondax/ledger-js'

import {PUBKEYLEN} from './consts'
import {ResponseSign, ResponseAddress, StdSigData, StdSignMetadata, StdSigDataResponse} from './types'

enum ArbitrarySignError {
  ErrorInvalidScope = 0x6988,
  ErrorFailedDecoding = 0x6989,
  ErrorInvalidSigner = 0x698A,
  ErrorMissingDomain = 0x698B,
  ErrorMissingAuthenticatedData = 0x698C,
  ErrorBadJson = 0x698D,
  ErrorFailedDomainAuth = 0x698E,
  ErrorFailedHdPath = 0x698F,
}

const ARBITRARY_SIGN_ERROR_DESCRIPTIONS = {
  ...ERROR_DESCRIPTION_OVERRIDE,
  [ArbitrarySignError.ErrorInvalidScope]: "Invalid Scope",
  [ArbitrarySignError.ErrorFailedDecoding]: "Failed decoding",
  [ArbitrarySignError.ErrorInvalidSigner]: "Invalid Signer",
  [ArbitrarySignError.ErrorMissingDomain]: "Missing Domain",
  [ArbitrarySignError.ErrorMissingAuthenticatedData]: "Missing Authentication Data",
  [ArbitrarySignError.ErrorBadJson]: "Bad JSON",
  [ArbitrarySignError.ErrorFailedDomainAuth]: "Failed Domain Auth",
  [ArbitrarySignError.ErrorFailedHdPath]: "Failed HD Path",
}

export class AlgorandApp extends BaseApp {
    static _INS = {
        GET_VERSION: 0x00 as number,
        GET_PUBLIC_KEY: 0x03 as number,
        GET_ADDRESS: 0x04 as number,
        SIGN_MSGPACK: 0x08 as number,
        SIGN_ARBITRARY: 0x10 as number,
    }

    static _params = {
        cla: 0x80,
        ins: {...AlgorandApp._INS} as INSGeneric,
        p1Values: {ONLY_RETRIEVE: 0x00 as 0, SHOW_ADDRESS_IN_DEVICE: 0x01 as 1},
        p1ValuesSign: {P1_FIRST: 0x00 as 0, P1_FIRST_ACCOUNT_ID: 0x01 as 1, P1_FIRST_HDPATH: 0x02 as 2, P1_MORE: 0x80 as 128, P1_WITH_REQUEST_USER_APPROVAL: 0x80 as 128},
        p2Values: {P2_MORE_CHUNKS: 0x80 as 128, P2_LAST_CHUNK: 0x00 as 0},
        chunkSize: 250,
        requiredPathLengths: [5],
    }

    constructor(transport: Transport) {
        super(transport, AlgorandApp._params)
        if (!this.transport) {
            throw new Error('Transport has not been defined')
        }
    }

  private prepareChunksWithAccountId(accountId: number, message: Buffer): Buffer[] {
    const chunks = this.messageToChunks(message)
    const accountIdBuffer = Buffer.alloc(4);
    accountIdBuffer.writeUInt32BE(accountId)
    chunks.unshift(accountIdBuffer)
    return chunks
  }

  private extractAccountIdFromSerializedPath(path: Buffer): number {
    const HARDENED = 0x80000000;
    const accountId = path.readUInt32LE(8) & ~HARDENED;
    return accountId;
  }

    protected async sendGenericChunk(ins: number, p2: number, chunkIdx: number, chunkNum: number, chunk: Buffer, p1?: number): Promise<ResponsePayload> {
        if (p1 === undefined) {
            p1 = chunkIdx === 0 ? AlgorandApp._params.p1ValuesSign.P1_FIRST_ACCOUNT_ID : AlgorandApp._params.p1ValuesSign.P1_MORE;
        }

        const statusList = [LedgerError.NoErrors, LedgerError.DataIsInvalid, LedgerError.BadKeyHandle]

        const responseBuffer = await this.transport.send(this.CLA, ins, p1, p2, chunk, statusList)
        const response = processResponse(responseBuffer, this.CUSTOM_APP_ERROR_DESCRIPTION)

        return response
    }

    async getAddressAndPubKey(path: string, showAddrInDevice = false): Promise<ResponseAddress> {
        const bip44PathBuffer = this.serializePath(path)
        const p1 = showAddrInDevice ? AlgorandApp._params.p1Values.SHOW_ADDRESS_IN_DEVICE : AlgorandApp._params.p1Values.ONLY_RETRIEVE
        const accountId = this.extractAccountIdFromSerializedPath(bip44PathBuffer)
        const data = Buffer.alloc(4);
        data.writeUInt32BE(accountId)

        try {
            const responseBuffer = await this.transport.send(AlgorandApp._params.cla, AlgorandApp._INS.GET_ADDRESS, p1, 0, data)

            const response = processResponse(responseBuffer)

            const pubkey = response.readBytes(PUBKEYLEN)
            const address = response.getAvailableBuffer().toString()

            console.log(pubkey.toString('hex'))
            console.log(address)

            return {
                pubkey,
                address,
            } as ResponseAddress
        } catch (e) {
            throw processErrorResponse(e)
        }
    }

    async getPubkey(path: string, showAddrInDevice = false): Promise<ResponseAddress> {
        const bip44PathBuffer = this.serializePath(path)
        const p1 = showAddrInDevice ? AlgorandApp._params.p1Values.SHOW_ADDRESS_IN_DEVICE : AlgorandApp._params.p1Values.ONLY_RETRIEVE
        const accountId = this.extractAccountIdFromSerializedPath(bip44PathBuffer)
        const data = Buffer.alloc(4);
        data.writeUInt32BE(accountId)

        try {
            const responseBuffer = await this.transport.send(AlgorandApp._params.cla, AlgorandApp._INS.GET_PUBLIC_KEY, p1, 0, data)

            const response = processResponse(responseBuffer)

            return {
                pubkey: response.readBytes(PUBKEYLEN),
                address: response.getAvailableBuffer().toString(),
            } as ResponseAddress
        } catch (e) {
            throw processErrorResponse(e)
        }
    }

    async getVersion() : Promise<ResponseVersion> {
      try {
        const responseBuffer = await this.transport.send(AlgorandApp._params.cla, AlgorandApp._INS.GET_VERSION, 0, 0)

        const response = processResponse(responseBuffer)

        const testMode = response.readBytes(1)[0] !== 0
        const major = response.readBytes(2).readUInt16BE(0)
        const minor = response.readBytes(2).readUInt16BE(0)
        const patch = response.readBytes(2).readUInt16BE(0)
        const deviceLocked = response.readBytes(1)[0] === 1
        const targetId = response.readBytes(4).toString('hex')

        return {
          testMode,
          major,
          minor,
          patch,
          deviceLocked,
          targetId,
        } as ResponseVersion
      } catch (e) {
        throw processErrorResponse(e)
      }
  }

    async sign(path: BIP32Path, blob: Buffer): Promise<ResponseSign> {
        const bip44PathBuffer = this.serializePath(path)
        const accountId = this.extractAccountIdFromSerializedPath(bip44PathBuffer)
        const chunks = this.prepareChunksWithAccountId(accountId, blob);

        let p2 = (chunks.length > 1) ? AlgorandApp._params.p2Values.P2_MORE_CHUNKS : AlgorandApp._params.p2Values.P2_LAST_CHUNK;

        try {
            let signatureResponse = await this.sendGenericChunk(AlgorandApp._INS.SIGN_MSGPACK, p2, 0, chunks.length, chunks[0])

            for (let i = 1; i < chunks.length; i += 1) {
                p2 = (i < chunks.length - 1) ? AlgorandApp._params.p2Values.P2_MORE_CHUNKS : AlgorandApp._params.p2Values.P2_LAST_CHUNK;
                signatureResponse = await this.sendGenericChunk(AlgorandApp._INS.SIGN_MSGPACK, p2, i, chunks.length, chunks[i])
            }

            return {
                signature: signatureResponse.readBytes(signatureResponse.length()),
            }

        } catch (e) {
            throw processErrorResponse(e)
        }
    }

    async signData(signingData: StdSigData, metadata: StdSignMetadata): Promise<StdSigDataResponse> {
        const dataBuffer = Buffer.isBuffer(signingData.data) ? signingData.data : Buffer.from(signingData.data);
        const signerBuffer = Buffer.from(signingData.signer || '');
        const domainBuffer = Buffer.from(signingData.domain || '');
        const authDataBuffer = Buffer.from(signingData.authenticationData || '');
        const requestIdBuffer = Buffer.from(signingData.requestId || '');
        
        const pathBuffer = signingData.hdPath ? this.serializePath(signingData.hdPath) : this.serializePath("m/44'/283'/0'/0/0");

        const messageSize = 
            4 + dataBuffer.length +
            4 + signerBuffer.length +
            4 + domainBuffer.length +
            4 + authDataBuffer.length +
            4 + requestIdBuffer.length;
        
        const messageBuffer = Buffer.alloc(messageSize);
        let offset = 0;
        
        function writeField(buffer: Buffer) {
            messageBuffer.writeUInt32BE(buffer.length, offset);
            offset += 4;
            buffer.copy(messageBuffer, offset);
            offset += buffer.length;
        }
        
        writeField(dataBuffer);
        writeField(signerBuffer);
        writeField(domainBuffer);
        writeField(authDataBuffer);
        writeField(requestIdBuffer);
        
        const chunks = this.messageToChunks(messageBuffer);
        
        let signature: Buffer;

        try {
            const firstChunk = pathBuffer;
            
            let p2: number = AlgorandApp._params.p2Values.P2_MORE_CHUNKS;
            
            let response = await this.sendGenericChunk(AlgorandApp._INS.SIGN_ARBITRARY, p2, 0, chunks.length + 1, firstChunk, AlgorandApp._params.p1ValuesSign.P1_FIRST_HDPATH);
            
            for (let i = 0; i < chunks.length; i++) {
                p2 = (i < chunks.length - 1) ? 
                    AlgorandApp._params.p2Values.P2_MORE_CHUNKS : 
                    AlgorandApp._params.p2Values.P2_LAST_CHUNK;
                
                response = await this.sendGenericChunk(
                    AlgorandApp._INS.SIGN_ARBITRARY, 
                    p2, 
                    i + 1, 
                    chunks.length + 1, 
                    chunks[i]
                );
            }
            
            signature = response.readBytes(response.length());
        } catch (e) {
            throw processErrorResponse(e, ARBITRARY_SIGN_ERROR_DESCRIPTIONS);
        }

        return {
            data: signingData.data,
            signer: signingData.signer,
            domain: signingData.domain,
            authenticationData: signingData.authenticationData,
            requestId: signingData.requestId,
            hdPath: signingData.hdPath,
            signature: signature,
        }
    }
}
