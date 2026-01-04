import { config } from '../environment';

describe('Environment Configuration', () => {
  it('should load configuration values', () => {
    expect(config.port).toBeDefined();
    expect(config.nodeEnv).toBeDefined();
    expect(config.mongodbUri).toBeDefined();
    expect(config.jwtSecret).toBeDefined();
    expect(config.encryptionKey).toBeDefined();
  });

  it('should have correct default values', () => {
    expect(config.nodeEnv).toBe('test'); // Set in test setup
    expect(config.port).toBeGreaterThan(0);
    expect(config.redisHost).toBe('localhost');
    expect(config.redisPort).toBe(6379);
  });

  it('should validate required environment variables', () => {
    expect(config.jwtSecret).toBeTruthy();
    expect(config.encryptionKey).toBeTruthy();
    expect(config.mongodbUri).toBeTruthy();
  });
});
