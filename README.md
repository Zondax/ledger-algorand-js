# @zondax/ledger-algorand

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![npm version](https://badge.fury.io/js/%40zondax%2Fledger-algorand.svg)](https://badge.fury.io/js/%40zondax%2Fledger-algorand)

This package provides a basic client library to communicate with the Algorand App running in a Ledger Nano S/X

We recommend using this npm package in order to receive updates/fixes.

# Integration Guidance

### Transport Options

To use this library, you need to create a transport instance that connects to your Ledger device. The transport layer handles communication between your application and the Ledger hardware wallet. Choose a transport based on your application environment:

#### Available Transport Packages

| Transport Package                                                                                                      | Environment          |
| ---------------------------------------------------------------------------------------------------------------------- | -------------------- |
| [`@ledgerhq/hw-transport-webusb`](https://www.npmjs.com/package/@ledgerhq/hw-transport-webusb)                         | Web                  |
| [`@ledgerhq/hw-transport-web-ble`](https://www.npmjs.com/package/@ledgerhq/hw-transport-web-ble)                       | Web (with Bluetooth) |
| [`@ledgerhq/hw-transport-node-hid`](https://www.npmjs.com/package/@ledgerhq/hw-transport-node-hid)                     | Node/Electron        |
| [`@ledgerhq/hw-transport-node-hid-singleton`](https://www.npmjs.com/package/@ledgerhq/hw-transport-node-hid-singleton) | Node.js/Electron     |
| [`@ledgerhq/hw-transport-http`](https://www.npmjs.com/package/@ledgerhq/hw-transport-http)                             | Any                  |

## API

### getVersion

The `getVersion` method retrieves the version information from the Algorand Ledger app.

```typescript
import { AlgorandApp } from '@zondax/ledger-algorand'

// Select transport based on your needs
const transport = getTransport()
const app = new AlgorandApp(transport)

try {
  const response = await app.getVersion()
  console.log(`Version: ${response.major}.${response.minor}.${response.patch}`)
  console.log(`Test mode: ${response.testMode}`)
  console.log(`Device locked: ${response.deviceLocked}`)
} catch (error) {
  // Handle error
} finally {
  transport.close()
}
```

### getAddressAndPubKey

The `getAddressAndPubKey` method retrieves the Algorand public key and address from the Ledger device.

```typescript
import { AlgorandApp } from '@zondax/ledger-algorand'

// Select transport based on your needs
const transport = getTransport()
const app = new AlgorandApp(transport)

try {
  // Parameters:
  // accountId (optional): defaults to 0
  // requireConfirmation (optional): if true, shows the address on device for verification
  const response = await app.getAddressAndPubKey(0, false)
  console.log('Address:', response.address.toString())
  console.log('Public Key:', response.publicKey.toString('hex'))
} catch (error) {
  // Handle error
} finally {
  transport.close()
}
```

### sign

The `sign` method allows you to sign a transaction with the Algorand Ledger app.

```typescript
import { AlgorandApp } from '@zondax/ledger-algorand'

// Select transport based on your needs
const transport = getTransport()
const app = new AlgorandApp(transport)

// Blob to sign (Algorand transaction)
const txBlob = Buffer.from(transaction)

try {
  // Parameters:
  // accountId (optional): defaults to 0
  // txBlob: string or Buffer containing the data to sign
  const response = await app.sign(0, txBlob)
  console.log('Signature:', response.signature.toString('hex'))
} catch (error) {
  // Handle error
} finally {
  transport.close()
}
```

### SignData

The `signData` method allows you to sign arbitrary data with the Algorand Ledger app.

```typescript
import { createHash } from 'crypto'
import {
  AlgorandApp,
  ResponseAddress,
  ScopeType,
  StdSigData,
} from '@zondax/ledger-algorand'

// Import or define your canonify function

// Select transport based on your needs
const transport = getTransport()
const app = new AlgorandApp(transport)

const addressAndPubkey: ResponseAddress = await app.getAddressAndPubKey()
const pubBuf = addressAndPubkey.publicKey

const req = {
  type: 'foo',
  origin: 'bar',
}

const domain: string = 'dummyDomain'

const signingData: StdSigData = {
  // Base64-encoded canonified JSON
  data: Buffer.from(canonify(req)).toString('base64'),
  signer: pubBuf,
  domain: domain,
  // Uppercase Hex String, Base64-encoded
  requestId: Buffer.from(Array(32).fill(0x41)).toString('base64'),
  authenticationData: new Uint8Array(
    createHash('sha256').update(domain).digest()
  ),
  hdPath: "m/44'/283'/0'/0/0",
}

const metadata = {
  scope: ScopeType.AUTH,
  encoding: 'base64',
}

try {
  const response = await app.signData(signingData, metadata)
  console.log('Signature:', response.signature.toString())
} catch (error: any) {
  // Handle error
} finally {
  transport.close()
}
```

#### metadata

- `scope` (number): Scope identifier (currently only `ScopeType.AUTH` (1) is supported)
- `encoding` (string): Data encoding format (currently only "base64" is supported)

#### Error Handling (signData specific)

The signData method may throw specific errors. These errors are available in the app's [APDUSPEC](https://github.com/Zondax/ledger-algorand/blob/main/docs/APDUSPEC.md#arbitrary-sign-return-codes)

## Notes

Use `bun install` to avoid issues.
