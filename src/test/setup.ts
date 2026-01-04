// Global test setup
beforeAll(async () => {
  // Set test environment
  process.env.NODE_ENV = 'test';
}, 10000);

// Global test teardown
afterAll(async () => {
  // Cleanup will be handled by individual tests as needed
}, 10000);
