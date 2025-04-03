// Dummy test to make sure the vitest environment is working
import { describe, it, expect, beforeEach } from 'vitest'
import { AlgorandApp } from './app'
import TransportMock from '@ledgerhq/hw-transport-mocker'

describe('AlgorandApp', () => {
  let app: AlgorandApp

  beforeEach(async () => {

  })

  describe('prepareChunksFromAccountId', () => {
    it('should correctly chunk message with account id 0', () => {
      const message = Buffer.from('test message')
      const chunks = AlgorandApp.prepareChunksFromAccountId(0, message)
      
      expect(chunks).toBeInstanceOf(Array)
      expect(chunks[0]).toEqual(Buffer.from('test message'))
    })

    it('should prepend non-zero account id to message', () => {
      const message = Buffer.from('test message')
      const accountId = 1
      const chunks = AlgorandApp.prepareChunksFromAccountId(accountId, message)
      
      const accountIdBuffer = Buffer.alloc(4)
      accountIdBuffer.writeUInt32BE(accountId)
      const expectedBuffer = Buffer.concat([accountIdBuffer, message])
      
      expect(chunks[0]).toEqual(expectedBuffer)
    })
  })
}) 