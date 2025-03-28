import { beforeEach, describe, expect, it, vi } from 'vitest'
import Transport from '@ledgerhq/hw-transport'
import { LedgerError } from '../common'
import AlgorandApp from '../index'

// Mock the Transport class
const mockSend = vi.fn()
const mockClose = vi.fn()

vi.mock('@ledgerhq/hw-transport', () => ({
  default: class MockTransport {
    send = mockSend
    close = mockClose
  },
}))

describe('AlgorandApp', () => {
  let transport: Transport
  let app: AlgorandApp

  beforeEach(() => {
    transport = new Transport()
    app = new AlgorandApp(transport)
    vi.clearAllMocks()
  })

  describe('getVersion', () => {
    it('should return version information', async () => {
      // Mock response format:
      // [0] - test mode flag
      // [1-3] - version (major, minor, patch)
      // [4] - device locked flag
      // [5-8] - target ID
      // [9-10] - return code
      const mockResponse = Buffer.from([
        0, // test mode: false
        2,
        0,
        0, // version: 2.0.0
        0, // device locked: false
        0,
        0,
        0,
        0, // target ID: 0
        0x90,
        0x00, // return code: NoErrors
      ])
      mockSend.mockResolvedValue(mockResponse)

      const result = await app.getVersion()
      expect(result).toBeDefined()
      expect(result.major).toBe(2)
      expect(result.minor).toBe(0)
      expect(result.patch).toBe(0)
      expect(result.returnCode).toBe(LedgerError.NoErrors)
      expect(result.testMode).toBe(false)
      expect(result.deviceLocked).toBe(false)
      expect(result.targetId).toBe('0')
    })
  })

  describe('prepareChunks', () => {
    it('should prepare message chunks correctly', () => {
      const message = Buffer.from('test message')
      const accountId = 0
      const chunks = AlgorandApp.prepareChunks(accountId, message)

      expect(chunks).toBeInstanceOf(Array)
      expect(chunks.length).toBeGreaterThan(0)
      expect(chunks[0]).toBeInstanceOf(Buffer)
    })
  })

  describe('getPubkey', () => {
    it('should return public key and address', async () => {
      const mockResponse = Buffer.from([
        // Mock public key (32 bytes)
        ...Array(32).fill(1),
        // Mock address (58 bytes)
        ...Array(58).fill(2),
        // Return code (2 bytes)
        0x90,
        0x00,
      ])
      mockSend.mockResolvedValue(mockResponse)

      const result = await app.getPubkey()
      expect(result).toBeDefined()
      expect(result.publicKey).toBeDefined()
      expect(result.address).toBeDefined()
      expect(result.returnCode).toBe(LedgerError.NoErrors)
    })
  })

  describe('sign', () => {
    it('should sign a message', async () => {
      const message = 'test message'
      const accountId = 0
      const mockResponse = Buffer.from([
        // Mock signature (64 bytes)
        ...Array(64).fill(1),
        // Return code (2 bytes)
        0x90,
        0x00,
      ])
      mockSend.mockResolvedValue(mockResponse)

      const result = await app.sign(accountId, message)
      expect(result).toBeDefined()
      expect(result.signature).toBeDefined()
      expect(result.return_code).toBe(LedgerError.NoErrors)
    })
  })
})
