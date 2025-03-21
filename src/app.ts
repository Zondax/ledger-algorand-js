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
import BaseApp, {BIP32Path, INSGeneric, LedgerError, processErrorResponse, processResponse, ResponsePayload, ResponseVersion} from '@zondax/ledger-js'

import {PUBKEYLEN} from './consts'
import {ResponseSign, ResponseAddress} from './types'

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
        p1ValuesSign: {P1_FIRST: 0x00 as 0, P1_FIRST_ACCOUNT_ID: 0x01 as 1, P1_MORE: 0x80 as 128, P1_WITH_REQUEST_USER_APPROVAL: 0x80 as 128},
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

    protected async sendGenericChunk(ins: number, p2: number, chunkIdx: number, chunkNum: number, chunk: Buffer): Promise<ResponsePayload> {
        const p1 = chunkIdx === 0 ? AlgorandApp._params.p1ValuesSign.P1_FIRST_ACCOUNT_ID : AlgorandApp._params.p1ValuesSign.P1_MORE;

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

   async signData() {
    // TODO: Implement
   }
}
