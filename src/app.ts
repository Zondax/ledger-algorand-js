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
import BaseApp, {
  BIP32Path,
  ERROR_DESCRIPTION_OVERRIDE,
  INSGeneric,
  processErrorResponse,
  processResponse,
  ResponsePayload,
} from '@zondax/ledger-js'
import { ERROR_DESCRIPTION, LedgerError } from './common'
import { PUBKEYLEN } from './consts'
import {
  ResponseAddress,
  ResponseSign,
  ResponseVersion,
  StdSigData,
  StdSigDataResponse,
  StdSignMetadata,
} from './types'

// Add this constant for the default signing path
const DEFAULT_SIGN_DATA_PATH = "m/44'/283'/0'/0/0"

enum ArbitrarySignError {
  ErrorInvalidScope = 0x6988,
  ErrorFailedDecoding = 0x6989,
  ErrorInvalidSigner = 0x698a,
  ErrorMissingDomain = 0x698b,
  ErrorMissingAuthenticatedData = 0x698c,
  ErrorBadJson = 0x698d,
  ErrorFailedDomainAuth = 0x698e,
  ErrorFailedHdPath = 0x698f,
}

const ARBITRARY_SIGN_ERROR_DESCRIPTIONS = {
  ...ERROR_DESCRIPTION_OVERRIDE,
  [ArbitrarySignError.ErrorInvalidScope]: 'Invalid Scope',
  [ArbitrarySignError.ErrorFailedDecoding]: 'Failed decoding',
  [ArbitrarySignError.ErrorInvalidSigner]: 'Invalid Signer',
  [ArbitrarySignError.ErrorMissingDomain]: 'Missing Domain',
  [ArbitrarySignError.ErrorMissingAuthenticatedData]:
    'Missing Authentication Data',
  [ArbitrarySignError.ErrorBadJson]: 'Bad JSON',
  [ArbitrarySignError.ErrorFailedDomainAuth]: 'Failed Domain Auth',
  [ArbitrarySignError.ErrorFailedHdPath]: 'Failed HD Path',
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
    ins: { ...AlgorandApp._INS } as INSGeneric,
    p1Values: { ONLY_RETRIEVE: 0x00 as 0, SHOW_ADDRESS_IN_DEVICE: 0x01 as 1 },
    p1ValuesSignLegacy: {
      P1_FIRST: 0x00 as 0,
      P1_FIRST_ACCOUNT_ID: 0x01 as 1,
      P1_MORE: 0x80 as 128,
      P1_WITH_REQUEST_USER_APPROVAL: 0x80 as 128,
    },
    p1ValuesSignArbitrary: {
      P1_INIT: 0x00 as 0,
      P1_ADD: 0x01 as 1,
      P1_LAST: 0x02 as 2,
    },
    p2Values: { P2_MORE_CHUNKS: 0x80 as 128, P2_LAST_CHUNK: 0x00 as 0 },
    chunkSize: 250,
    requiredPathLengths: [5],
  }

  constructor(transport: Transport) {
    super(transport, AlgorandApp._params)
    if (!this.transport) {
      throw new Error('Transport has not been defined')
    }
  }

  protected async sendGenericChunk(
    ins: number,
    p2: number,
    chunkIdx: number,
    chunkNum: number,
    chunk: Buffer,
    p1?: number
  ): Promise<ResponsePayload> {
    if (p1 === undefined) {
      p1 =
        chunkIdx === 0
          ? AlgorandApp._params.p1ValuesSignLegacy.P1_FIRST_ACCOUNT_ID
          : AlgorandApp._params.p1ValuesSignLegacy.P1_MORE
    }

    const statusList = [
      LedgerError.NoErrors,
      LedgerError.DataIsInvalid,
      LedgerError.BadKeyHandle,
    ]

    const responseBuffer = await this.transport.send(
      this.CLA,
      ins,
      p1,
      p2,
      chunk,
      statusList
    )
    const response = processResponse(
      responseBuffer,
      this.CUSTOM_APP_ERROR_DESCRIPTION
    )

    return response
  }

  async signGetChunks(accountId: number, message: string | Buffer) {
    return AlgorandApp.prepareChunksFromAccountId(accountId, message)
  }

  static prepareChunksFromAccountId(
    accountId: number,
    message: string | Buffer
  ) {
    const chunks = []

    // First chunk prepend accountId if != 0
    let messageBuffer

    if (typeof message === 'string') {
      messageBuffer = Buffer.from(message)
    } else {
      messageBuffer = message
    }

    let buffer: Buffer

    if (accountId !== 0) {
      const accountIdBuffer = Buffer.alloc(4)
      accountIdBuffer.writeUInt32BE(accountId)
      buffer = Buffer.concat([accountIdBuffer, messageBuffer])
    } else {
      buffer = Buffer.concat([messageBuffer])
    }

    for (let i = 0; i < buffer.length; i += AlgorandApp._params.chunkSize) {
      let end = i + AlgorandApp._params.chunkSize
      if (i > buffer.length) {
        end = buffer.length
      }
      chunks.push(buffer.slice(i, end))
    }

    return chunks
  }

  async getVersion(): Promise<ResponseVersion> {
    const response = await super.getVersion()
    return {
      ...response,
      returnCode: LedgerError.NoErrors,
      errorMessage: ERROR_DESCRIPTION[LedgerError.NoErrors],
      // Legacy
      return_code: LedgerError.NoErrors,
      error_message: ERROR_DESCRIPTION[LedgerError.NoErrors],
    } as ResponseVersion
  }

  async getAddressAndPubKey(
    accountId = 0,
    requireConfirmation = false
  ): Promise<ResponseAddress> {
    const p1 = requireConfirmation
      ? AlgorandApp._params.p1Values.SHOW_ADDRESS_IN_DEVICE
      : AlgorandApp._params.p1Values.ONLY_RETRIEVE
    const data = Buffer.alloc(4)
    data.writeUInt32BE(accountId)

    try {
      const responseBuffer = await this.transport.send(
        AlgorandApp._params.cla,
        AlgorandApp._INS.GET_ADDRESS,
        p1,
        0,
        data
      )

      const response = processResponse(responseBuffer)

      const pubkey = response.readBytes(PUBKEYLEN)
      const address = response.getAvailableBuffer().toString()

      return {
        publicKey: Buffer.from(pubkey),
        address: Buffer.from(address),
        returnCode: LedgerError.NoErrors,
        errorMessage: ERROR_DESCRIPTION[LedgerError.NoErrors],
        // Legacy
        bech32_address: Buffer.from(address),
        compressed_pk: Buffer.from(pubkey),
        return_code: LedgerError.NoErrors,
        error_message: ERROR_DESCRIPTION[LedgerError.NoErrors],
      } as ResponseAddress
    } catch (e) {
      throw processErrorResponse(e)
    }
  }

  async sign(accountId = 0, message: string | Buffer): Promise<ResponseSign> {
    const chunks = AlgorandApp.prepareChunksFromAccountId(accountId, message)

    let p2 =
      chunks.length > 1
        ? AlgorandApp._params.p2Values.P2_MORE_CHUNKS
        : AlgorandApp._params.p2Values.P2_LAST_CHUNK

    try {
      let signatureResponse = await this.sendGenericChunk(
        AlgorandApp._INS.SIGN_MSGPACK,
        p2,
        0,
        chunks.length,
        chunks[0]
      )

      for (let i = 1; i < chunks.length; i += 1) {
        p2 =
          i < chunks.length - 1
            ? AlgorandApp._params.p2Values.P2_MORE_CHUNKS
            : AlgorandApp._params.p2Values.P2_LAST_CHUNK
        signatureResponse = await this.sendGenericChunk(
          AlgorandApp._INS.SIGN_MSGPACK,
          p2,
          i,
          chunks.length,
          chunks[i]
        )
      }

      return {
        signature: signatureResponse.readBytes(signatureResponse.length()),
        returnCode: LedgerError.NoErrors,
        errorMessage: ERROR_DESCRIPTION[LedgerError.NoErrors],
        // Legacy
        return_code: LedgerError.NoErrors,
        error_message: ERROR_DESCRIPTION[LedgerError.NoErrors],
      } as ResponseSign
    } catch (e) {
      throw processErrorResponse(e)
    }
  }

  /**
   * @deprecated Use getAddressAndPubKey instead
   */
  async getPubkey(
    accountId = 0,
    requireConfirmation = false
  ): Promise<ResponseAddress> {
    const p1 = requireConfirmation
      ? AlgorandApp._params.p1Values.SHOW_ADDRESS_IN_DEVICE
      : AlgorandApp._params.p1Values.ONLY_RETRIEVE
    const data = Buffer.alloc(4)
    data.writeUInt32BE(accountId)

    try {
      const responseBuffer = await this.transport.send(
        AlgorandApp._params.cla,
        AlgorandApp._INS.GET_PUBLIC_KEY,
        p1,
        0,
        data
      )

      const response = processResponse(responseBuffer)

      const pubkey = response.readBytes(PUBKEYLEN)
      const address = response.getAvailableBuffer().toString()

      return {
        publicKey: Buffer.from(pubkey),
        address: Buffer.from(address),
        returnCode: LedgerError.NoErrors,
        errorMessage: ERROR_DESCRIPTION[LedgerError.NoErrors],
        // Legacy
        bech32_address: Buffer.from(address),
        compressed_pk: Buffer.from(pubkey),
        return_code: LedgerError.NoErrors,
        error_message: ERROR_DESCRIPTION[LedgerError.NoErrors],
      } as ResponseAddress
    } catch (e) {
      throw processErrorResponse(e)
    }
  }

  async signData(
    signingData: StdSigData,
    metadata: StdSignMetadata
  ): Promise<StdSigDataResponse> {
    let dataToEncode
    let decodedData

    if (metadata.encoding === 'base64') {
      decodedData = Buffer.from(signingData.data, 'base64')
    } else {
      throw new Error('Failed decoding')
    }

    const signerBuffer = Buffer.from(signingData.signer)
    const scopeBuffer = Buffer.from([metadata.scope])
    const encodingBuffer = serializeEncoding(metadata.encoding)
    const dataBuffer = decodedData
    const domainBuffer = signingData.domain
      ? Buffer.from(signingData.domain)
      : Buffer.from([])
    const requestIdBuffer = signingData.requestId
      ? Buffer.from(signingData.requestId, 'base64')
      : Buffer.from([])
    const authDataBuffer = signingData.authenticationData
      ? Buffer.from(signingData.authenticationData)
      : Buffer.from([])
    const pathBuffer = signingData.hdPath
      ? this.serializePath(signingData.hdPath)
      : this.serializePath(DEFAULT_SIGN_DATA_PATH)

    const messageSize =
      signerBuffer.length +
      scopeBuffer.length +
      encodingBuffer.length +
      2 +
      dataBuffer.length +
      2 +
      domainBuffer.length +
      2 +
      requestIdBuffer.length +
      2 +
      authDataBuffer.length

    const messageBuffer = Buffer.alloc(messageSize)
    let offset = 0

    function writeField(buffer: Buffer, variableLength: boolean = false) {
      if (variableLength) {
        messageBuffer.writeUInt16BE(buffer.length, offset)
        offset += 2
      }
      buffer.copy(messageBuffer, offset)
      offset += buffer.length
    }

    writeField(signerBuffer)
    writeField(scopeBuffer)
    writeField(encodingBuffer)
    writeField(dataBuffer, true)
    writeField(domainBuffer, true)
    writeField(requestIdBuffer, true)
    writeField(authDataBuffer, true)

    const chunks = this.messageToChunks(messageBuffer)

    let signature: Buffer
    let p2 = 0 // Not used for arbitrary sign
    try {
      const firstChunk = pathBuffer

      let response = await this.sendGenericChunk(
        AlgorandApp._INS.SIGN_ARBITRARY,
        p2,
        0,
        chunks.length + 1,
        firstChunk,
        AlgorandApp._params.p1ValuesSignArbitrary.P1_INIT
      )

      for (let i = 0; i < chunks.length; i++) {
        const p1 =
          i < chunks.length - 1
            ? AlgorandApp._params.p1ValuesSignArbitrary.P1_ADD
            : AlgorandApp._params.p1ValuesSignArbitrary.P1_LAST

        response = await this.sendGenericChunk(
          AlgorandApp._INS.SIGN_ARBITRARY,
          p2,
          i + 1,
          chunks.length + 1,
          chunks[i],
          p1
        )
      }

      signature = response.readBytes(response.length())
    } catch (e) {
      throw processErrorResponse(e, ARBITRARY_SIGN_ERROR_DESCRIPTIONS)
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

function serializeEncoding(encoding: string): Buffer {
  switch (encoding) {
    case 'base64':
      return Buffer.from([0x01])
    default:
      throw new Error('Unsupported encoding')
  }
}
