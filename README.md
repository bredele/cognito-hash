# cognito-hash

Cognito base64-encoded HMAC SHA-256 hash.

## Installation

```sh
npm install cognito-hash
```

## API

`hash(username: string, clientId: string, clientSecret: string): Promise<string>`

Creates a base64-encoded HMAC SHA-256 hash for AWS Cognito authentication when a client secret is configured.

**Parameters:**
- `username` - The username for the Cognito user
- `clientId` - The Cognito app client ID
- `clientSecret` - The Cognito app client secret

**Returns:** `Promise<string>` - Base64-encoded HMAC SHA-256 hash

**Usage:**
```typescript
import hash from 'cognito-hash';

const secretHash = await hash('john.doe', 'your-client-id', 'your-client-secret');
```
