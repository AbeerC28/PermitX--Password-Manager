/**
 * Clipboard utility functions for secure password handling
 * Provides cross-browser compatibility and automatic clearing functionality
 */

export interface ClipboardOptions {
  clearAfter?: number; // Time in milliseconds to clear clipboard (default: 60000ms = 60s)
  fallbackMessage?: string; // Message to show if clipboard API is not available
}

export interface ClipboardResult {
  success: boolean;
  message: string;
  clearTimer?: NodeJS.Timeout;
}

/**
 * Checks if the Clipboard API is available in the current browser
 */
export const isClipboardSupported = (): boolean => {
  try {
    return (
      typeof navigator !== 'undefined' &&
      navigator !== null &&
      'clipboard' in navigator &&
      navigator.clipboard !== null &&
      'writeText' in navigator.clipboard &&
      typeof navigator.clipboard.writeText === 'function' &&
      // Check if we're in a secure context (required for Clipboard API)
      (window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost')
    );
  } catch (error) {
    console.warn('Error checking clipboard support:', error);
    return false;
  }
};

/**
 * Checks if the browser supports the legacy execCommand for clipboard operations
 */
export const isLegacyClipboardSupported = (): boolean => {
  try {
    return (
      typeof document !== 'undefined' &&
      document !== null &&
      'execCommand' in document &&
      typeof document.execCommand === 'function'
    );
  } catch (error) {
    console.warn('Error checking legacy clipboard support:', error);
    return false;
  }
};

/**
 * Copies text to clipboard using the modern Clipboard API
 */
const copyWithClipboardAPI = async (text: string): Promise<boolean> => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Clipboard API failed:', error);
    return false;
  }
};

/**
 * Copies text to clipboard using the legacy execCommand method
 */
const copyWithLegacyMethod = (text: string): boolean => {
  try {
    // Create a temporary textarea element
    const textarea = document.createElement('textarea');
    textarea.value = text;
    
    // Position the textarea off-screen but still accessible
    textarea.style.position = 'fixed';
    textarea.style.left = '-999999px';
    textarea.style.top = '-999999px';
    textarea.style.opacity = '0';
    textarea.style.pointerEvents = 'none';
    textarea.setAttribute('readonly', '');
    textarea.setAttribute('tabindex', '-1');
    
    // Add to DOM
    document.body.appendChild(textarea);
    
    // Focus and select the text
    textarea.focus();
    textarea.select();
    
    // For mobile devices, ensure the selection is complete
    if (textarea.setSelectionRange) {
      textarea.setSelectionRange(0, text.length);
    }
    
    // Execute the copy command
    const success = document.execCommand('copy');
    
    // Clean up
    document.body.removeChild(textarea);
    
    return success;
  } catch (error) {
    console.error('Legacy clipboard method failed:', error);
    return false;
  }
};

/**
 * Copies masked password to clipboard with automatic clearing
 * The password is never displayed in plain text for security
 */
export const copyPasswordToClipboard = async (
  maskedPassword: string,
  options: ClipboardOptions = {}
): Promise<ClipboardResult> => {
  const {
    clearAfter = 60000, // 60 seconds default as per requirement 4.3
    fallbackMessage = 'Please manually copy the password from the secure field'
  } = options;

  // Validate input
  if (!maskedPassword || typeof maskedPassword !== 'string') {
    return {
      success: false,
      message: 'Invalid password data provided'
    };
  }

  let success = false;
  let message = '';
  let clearTimer: NodeJS.Timeout | undefined;
  let method = '';

  // Try modern Clipboard API first
  if (isClipboardSupported()) {
    try {
      success = await copyWithClipboardAPI(maskedPassword);
      if (success) {
        method = 'Clipboard API';
        message = 'Password copied to clipboard successfully';
      }
    } catch (error) {
      console.warn('Clipboard API failed, trying fallback:', error);
    }
  }

  // Fallback to legacy method if modern API failed or is not available
  if (!success && isLegacyClipboardSupported()) {
    try {
      success = copyWithLegacyMethod(maskedPassword);
      if (success) {
        method = 'legacy method';
        message = 'Password copied to clipboard successfully (legacy method)';
      }
    } catch (error) {
      console.warn('Legacy clipboard method failed:', error);
    }
  }

  // If both methods failed
  if (!success) {
    return {
      success: false,
      message: fallbackMessage
    };
  }

  // Set up automatic clipboard clearing for security (requirement 4.3)
  if (clearAfter > 0) {
    clearTimer = setTimeout(async () => {
      try {
        let cleared = false;
        
        // Try to clear using the same method that worked for copying
        if (method === 'Clipboard API' && isClipboardSupported()) {
          await navigator.clipboard.writeText('');
          cleared = true;
        } else if (method === 'legacy method' && isLegacyClipboardSupported()) {
          cleared = copyWithLegacyMethod('');
        }
        
        if (cleared) {
          console.log('Clipboard cleared for security after', clearAfter, 'ms');
        } else {
          console.warn('Failed to clear clipboard automatically');
        }
      } catch (error) {
        console.error('Failed to clear clipboard:', error);
      }
    }, clearAfter);

    message += ` (will be cleared in ${Math.round(clearAfter / 1000)} seconds)`;
  }

  return {
    success: true,
    message,
    clearTimer
  };
};

/**
 * Manually clears the clipboard
 */
export const clearClipboard = async (): Promise<boolean> => {
  try {
    if (isClipboardSupported()) {
      await navigator.clipboard.writeText('');
      return true;
    } else if (isLegacyClipboardSupported()) {
      return copyWithLegacyMethod('');
    }
    return false;
  } catch (error) {
    console.error('Failed to clear clipboard:', error);
    return false;
  }
};

/**
 * Gets detailed information about clipboard capabilities in the current browser
 */
export const getClipboardCapabilities = (): {
  supported: boolean;
  method: 'modern' | 'legacy' | 'none';
  features: string[];
  secureContext: boolean;
  userAgent: string;
} => {
  const features: string[] = [];
  let method: 'modern' | 'legacy' | 'none' = 'none';
  const secureContext = typeof window !== 'undefined' ? 
    (window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost') : 
    false;

  if (isClipboardSupported()) {
    method = 'modern';
    features.push('Clipboard API');
    features.push('Secure context');
    features.push('Async operations');
  } else if (isLegacyClipboardSupported()) {
    method = 'legacy';
    features.push('execCommand');
    features.push('Synchronous operations');
  }

  if (method !== 'none') {
    features.push('Auto-clear');
    features.push('Cross-browser compatibility');
    features.push('Security timeout');
  }

  return {
    supported: method !== 'none',
    method,
    features,
    secureContext,
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'Unknown'
  };
};

// Import React for the hook
import React from 'react';

/**
 * Hook for managing clipboard operations with React
 */
export const useClipboard = () => {
  const [isSupported] = React.useState(() => 
    isClipboardSupported() || isLegacyClipboardSupported()
  );
  
  const [lastCopyResult, setLastCopyResult] = React.useState<ClipboardResult | null>(null);

  const copyPassword = React.useCallback(async (
    maskedPassword: string,
    options?: ClipboardOptions
  ): Promise<ClipboardResult> => {
    const result = await copyPasswordToClipboard(maskedPassword, options);
    setLastCopyResult(result);
    return result;
  }, []);

  const clearClipboardManually = React.useCallback(async (): Promise<boolean> => {
    const success = await clearClipboard();
    if (success && lastCopyResult?.clearTimer) {
      clearTimeout(lastCopyResult.clearTimer);
      setLastCopyResult(prev => prev ? { ...prev, clearTimer: undefined } : null);
    }
    return success;
  }, [lastCopyResult]);

  // Cleanup timer on unmount
  React.useEffect(() => {
    return () => {
      if (lastCopyResult?.clearTimer) {
        clearTimeout(lastCopyResult.clearTimer);
      }
    };
  }, [lastCopyResult]);

  return {
    isSupported,
    copyPassword,
    clearClipboard: clearClipboardManually,
    lastResult: lastCopyResult
  };
};