/**
 * Tests for clipboard utility functions
 */

import { 
  isClipboardSupported, 
  isLegacyClipboardSupported, 
  copyPasswordToClipboard,
  clearClipboard 
} from '../clipboard';

// Mock the navigator and document objects
const mockNavigator = {
  clipboard: {
    writeText: jest.fn()
  }
};

const mockDocument = {
  createElement: jest.fn(),
  body: {
    appendChild: jest.fn(),
    removeChild: jest.fn()
  },
  execCommand: jest.fn()
};

// Store original values
const originalNavigator = global.navigator;
const originalDocument = global.document;

describe('Clipboard Utilities', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.clearAllTimers();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  afterAll(() => {
    // Restore original values
    Object.defineProperty(global, 'navigator', {
      value: originalNavigator,
      writable: true
    });
    Object.defineProperty(global, 'document', {
      value: originalDocument,
      writable: true
    });
  });

  describe('isClipboardSupported', () => {
    it('should return true when Clipboard API is available', () => {
      Object.defineProperty(global, 'navigator', {
        value: mockNavigator,
        writable: true
      });

      expect(isClipboardSupported()).toBe(true);
    });

    it('should return false when Clipboard API is not available', () => {
      Object.defineProperty(global, 'navigator', {
        value: {},
        writable: true
      });

      expect(isClipboardSupported()).toBe(false);
    });

    it('should return false when navigator is undefined', () => {
      Object.defineProperty(global, 'navigator', {
        value: undefined,
        writable: true
      });

      expect(isClipboardSupported()).toBe(false);
    });
  });

  describe('isLegacyClipboardSupported', () => {
    it('should return true when execCommand is available', () => {
      Object.defineProperty(global, 'document', {
        value: mockDocument,
        writable: true
      });

      expect(isLegacyClipboardSupported()).toBe(true);
    });

    it('should return false when execCommand is not available', () => {
      Object.defineProperty(global, 'document', {
        value: {},
        writable: true
      });

      expect(isLegacyClipboardSupported()).toBe(false);
    });

    it('should return false when document is undefined', () => {
      Object.defineProperty(global, 'document', {
        value: undefined,
        writable: true
      });

      expect(isLegacyClipboardSupported()).toBe(false);
    });
  });

  describe('copyPasswordToClipboard', () => {
    it('should successfully copy using Clipboard API', async () => {
      Object.defineProperty(global, 'navigator', {
        value: mockNavigator,
        writable: true
      });

      mockNavigator.clipboard.writeText.mockResolvedValue(undefined);

      const result = await copyPasswordToClipboard('test-password', { clearAfter: 5000 });

      expect(result.success).toBe(true);
      expect(result.message).toContain('Password copied to clipboard successfully');
      expect(result.clearTimer).toBeDefined();
      expect(mockNavigator.clipboard.writeText).toHaveBeenCalledWith('test-password');
    });

    it('should fallback to legacy method when Clipboard API fails', async () => {
      const mockTextarea = {
        value: '',
        style: {},
        setAttribute: jest.fn(),
        select: jest.fn(),
        setSelectionRange: jest.fn()
      };

      Object.defineProperty(global, 'navigator', {
        value: {
          clipboard: {
            writeText: jest.fn().mockRejectedValue(new Error('API failed'))
          }
        },
        writable: true
      });

      Object.defineProperty(global, 'document', {
        value: {
          ...mockDocument,
          createElement: jest.fn().mockReturnValue(mockTextarea),
          execCommand: jest.fn().mockReturnValue(true)
        },
        writable: true
      });

      const result = await copyPasswordToClipboard('test-password');

      expect(result.success).toBe(true);
      expect(result.message).toContain('legacy method');
      expect(mockDocument.createElement).toHaveBeenCalledWith('textarea');
      expect(mockDocument.execCommand).toHaveBeenCalledWith('copy');
    });

    it('should return failure when both methods fail', async () => {
      Object.defineProperty(global, 'navigator', {
        value: {
          clipboard: {
            writeText: jest.fn().mockRejectedValue(new Error('API failed'))
          }
        },
        writable: true
      });

      Object.defineProperty(global, 'document', {
        value: {
          ...mockDocument,
          createElement: jest.fn().mockReturnValue({}),
          execCommand: jest.fn().mockReturnValue(false)
        },
        writable: true
      });

      const result = await copyPasswordToClipboard('test-password');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Please manually copy');
    });

    it('should set up automatic clearing when clearAfter is specified', async () => {
      Object.defineProperty(global, 'navigator', {
        value: mockNavigator,
        writable: true
      });

      mockNavigator.clipboard.writeText.mockResolvedValue(undefined);

      const result = await copyPasswordToClipboard('test-password', { clearAfter: 1000 });

      expect(result.success).toBe(true);
      expect(result.clearTimer).toBeDefined();

      // Fast-forward time to trigger the clear
      jest.advanceTimersByTime(1000);

      expect(mockNavigator.clipboard.writeText).toHaveBeenCalledWith('');
    });

    it('should not set up clearing when clearAfter is 0', async () => {
      Object.defineProperty(global, 'navigator', {
        value: mockNavigator,
        writable: true
      });

      mockNavigator.clipboard.writeText.mockResolvedValue(undefined);

      const result = await copyPasswordToClipboard('test-password', { clearAfter: 0 });

      expect(result.success).toBe(true);
      expect(result.clearTimer).toBeUndefined();
    });
  });

  describe('clearClipboard', () => {
    it('should clear clipboard using Clipboard API', async () => {
      Object.defineProperty(global, 'navigator', {
        value: mockNavigator,
        writable: true
      });

      mockNavigator.clipboard.writeText.mockResolvedValue(undefined);

      const result = await clearClipboard();

      expect(result).toBe(true);
      expect(mockNavigator.clipboard.writeText).toHaveBeenCalledWith('');
    });

    it('should fallback to legacy method when Clipboard API is not available', async () => {
      const mockTextarea = {
        value: '',
        style: {},
        setAttribute: jest.fn(),
        select: jest.fn(),
        setSelectionRange: jest.fn()
      };

      Object.defineProperty(global, 'navigator', {
        value: {},
        writable: true
      });

      Object.defineProperty(global, 'document', {
        value: {
          ...mockDocument,
          createElement: jest.fn().mockReturnValue(mockTextarea),
          execCommand: jest.fn().mockReturnValue(true)
        },
        writable: true
      });

      const result = await clearClipboard();

      expect(result).toBe(true);
      expect(mockDocument.execCommand).toHaveBeenCalledWith('copy');
    });

    it('should return false when clearing fails', async () => {
      Object.defineProperty(global, 'navigator', {
        value: {
          clipboard: {
            writeText: jest.fn().mockRejectedValue(new Error('Clear failed'))
          }
        },
        writable: true
      });

      Object.defineProperty(global, 'document', {
        value: {},
        writable: true
      });

      const result = await clearClipboard();

      expect(result).toBe(false);
    });
  });
});