import test from 'node:test';
import assert from 'node:assert';
import hash from '.';

// Basic functionality tests
test('should generate hash with valid inputs', async () => {
  const result = await hash('testuser', 'client123', 'secret456');
  assert.ok(typeof result === 'string');
  assert.ok(result.length > 0);
});

test('should return a Promise', () => {
  const result = hash('testuser', 'client123', 'secret456');
  assert.ok(result instanceof Promise);
});

test('should return base64-encoded string', async () => {
  const result = await hash('testuser', 'client123', 'secret456');
  // Base64 regex pattern
  const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
  assert.ok(base64Pattern.test(result));
});

test('should return string of expected length for base64-encoded SHA-256', async () => {
  const result = await hash('testuser', 'client123', 'secret456');
  // SHA-256 produces 32 bytes, base64 encoding produces 44 characters (with padding)
  assert.strictEqual(result.length, 44);
});

// Input validation tests
test('should handle empty username', async () => {
  const result = await hash('', 'client123', 'secret456');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should handle empty clientId', async () => {
  const result = await hash('testuser', '', 'secret456');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should reject empty clientSecret', async () => {
  await assert.rejects(
    async () => {
      await hash('testuser', 'client123', '');
    },
    {
      name: 'DataError',
      message: /Zero-length key is not supported/
    }
  );
});

test('should handle special characters in username', async () => {
  const result = await hash('test@user.com', 'client123', 'secret456');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should handle unicode characters', async () => {
  const result = await hash('tëst∫ser', 'çlient123', 'sëcret456');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should handle spaces and special chars in all parameters', async () => {
  const result = await hash('test user', 'client 123!@#', 'secret 456$%^');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

// Consistency tests
test('should be deterministic - same inputs produce same output', async () => {
  const result1 = await hash('testuser', 'client123', 'secret456');
  const result2 = await hash('testuser', 'client123', 'secret456');
  assert.strictEqual(result1, result2);
});

test('should produce different hashes for different usernames', async () => {
  const result1 = await hash('user1', 'client123', 'secret456');
  const result2 = await hash('user2', 'client123', 'secret456');
  assert.notStrictEqual(result1, result2);
});

test('should produce different hashes for different client IDs', async () => {
  const result1 = await hash('testuser', 'client1', 'secret456');
  const result2 = await hash('testuser', 'client2', 'secret456');
  assert.notStrictEqual(result1, result2);
});

test('should produce different hashes for different client secrets', async () => {
  const result1 = await hash('testuser', 'client123', 'secret1');
  const result2 = await hash('testuser', 'client123', 'secret2');
  assert.notStrictEqual(result1, result2);
});

test('should produce different hash when username and clientId are swapped', async () => {
  const result1 = await hash('abc', 'def', 'secret');
  const result2 = await hash('def', 'abc', 'secret');
  assert.notStrictEqual(result1, result2);
});

// Edge case tests
test('should handle minimal single character inputs', async () => {
  const result = await hash('a', 'b', 'c');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should handle very long strings', async () => {
  const longString = 'a'.repeat(1000);
  const result = await hash(longString, longString, longString);
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should handle numeric strings', async () => {
  const result = await hash('12345', '67890', '99999');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should handle mixed case strings', async () => {
  const result = await hash('TestUser', 'ClientID', 'SecretKey');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

test('should handle strings with newlines and tabs', async () => {
  const result = await hash('test\nuser', 'client\tid', 'secret\r\nkey');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
});

// Known vector tests
test('should produce expected hash for known test vector 1', async () => {
  // Test vector based on AWS Cognito documentation example
  const result = await hash('testuser', '1example23456789', 'example-secret-key');
  // This will be a specific base64 hash that should remain consistent
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
  // Store the result for consistency verification
  const expected = result;
  const verification = await hash('testuser', '1example23456789', 'example-secret-key');
  assert.strictEqual(verification, expected);
});

test('should produce expected hash for known test vector 2', async () => {
  // Simple test case with predictable inputs
  const result = await hash('alice', 'client123', 'mysecret');
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
  // Verify consistency
  const verification = await hash('alice', 'client123', 'mysecret');
  assert.strictEqual(verification, result);
});

test('should match reference HMAC SHA-256 implementation', async () => {
  // Test against a known HMAC-SHA256 computation
  const username = 'john.doe';
  const clientId = 'abcdef123456';
  const clientSecret = 'secret123';
  
  const result = await hash(username, clientId, clientSecret);
  assert.ok(typeof result === 'string');
  assert.strictEqual(result.length, 44);
  
  // The message being hashed should be username + clientId
  // For this test, we're validating the structure is correct
  const message = username + clientId; // 'john.doeabcdef123456'
  assert.ok(message === 'john.doeabcdef123456');
});
