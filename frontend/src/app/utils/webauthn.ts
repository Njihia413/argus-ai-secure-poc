import axios from 'axios';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { toast } from 'sonner';
import { API_URL } from "@/app/utils/constants";

// Extend the Navigator interface to include the 'usb' property
interface NavigatorWithUSB extends Navigator {
    usb: {
        getDevices: () => Promise<any[]>;
        requestDevice: (options: { filters: any[] }) => Promise<any>;
    };
}

// Global flag to prevent multiple simultaneous authentication attempts
let authenticationInProgress = false;

// Function to fix base64url encoding
export const fixBase64Padding = (base64url: string): string => {
    if (!base64url) return '';
    return base64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((base64url.length + 3) % 4);
};

// Store token binding information
export const storeBindingData = (token: string, nonce: string): void => {
    // Store in session storage for security (cleared when browser is closed)
    sessionStorage.setItem('auth_token', token);
    sessionStorage.setItem('binding_nonce', nonce);

    // Also log to help with debugging
    console.log('Stored binding data:', { auth_token: token.substring(0, 8) + '...', binding_nonce: nonce.substring(0, 8) + '...' });
};

// Get binding data for API calls
export const getBindingData = (): Record<string, string> => {
    // Get from session storage
    const token = sessionStorage.getItem('auth_token');
    const nonce = sessionStorage.getItem('binding_nonce');

    if (!token || !nonce) {
        console.log('No binding data available in session storage');
        return {};
    }

    console.log('Retrieved binding data:', { auth_token: token.substring(0, 8) + '...', binding_nonce: nonce.substring(0, 8) + '...' });

    return {
        auth_token: token,
        binding_nonce: nonce
    };
};

// Clear binding data on logout
export const clearBindingData = (): void => {
    sessionStorage.removeItem('auth_token');
    sessionStorage.removeItem('binding_nonce');
    console.log('Binding data cleared from session storage');
};

/**
 * Check if WebAuthn is supported by the browser
 */
export const isWebAuthnSupported = (): boolean => {
    return window &&
        window.PublicKeyCredential !== undefined &&
        typeof window.PublicKeyCredential === 'function';
};

/**
 * Check if WebUSB is supported by the browser
 */
export const isWebUSBSupported = (): boolean => {
    return window &&
        'usb' in navigator &&
        typeof (navigator as Navigator & { usb: any }).usb.requestDevice === 'function';
};

/**
 * FIDO U2F USB vendor and product IDs for common security keys
 * This is a non-exhaustive list based on common security key manufacturers
 */
const FIDO_DEVICE_FILTERS = [
    // YubiKey
    { vendorId: 0x1050 },
    // Feitian
    { vendorId: 0x096e },
    // Google Titan/Feitian
    { vendorId: 0x18d1 },
    // SoloKeys
    { vendorId: 0x0483 },
    // Generic FIDO U2F
    { classCode: 0x0B }, // Smart Card
    { classCode: 0x03 }  // HID
];

/**
 * Check if security key is connected using WebUSB
 * This tries to detect a security key device without requiring user interaction
 */
export const checkSecurityKeyStatus = async (username: string): Promise<boolean> => {
    console.log("Checking security key status for user:", username);

    // First check if WebAuthn is supported by the browser
    if (!isWebAuthnSupported()) {
        console.warn('WebAuthn is not supported in this browser');
        return false;
    }

    try {
        // For production environments, we'll try different approaches in order:

        // 1. First, try to use the WebAuthn isUserVerifyingPlatformAuthenticatorAvailable API
        // This is a non-intrusive way to check if authenticator is available
        if ('isUserVerifyingPlatformAuthenticatorAvailable' in navigator.credentials) {
            try {
                const isPlatformAuthenticatorAvailable =
                    await (navigator.credentials as any).isUserVerifyingPlatformAuthenticatorAvailable();

                // If platform authenticator is available, we still need to check if it's a security key
                if (isPlatformAuthenticatorAvailable) {
                    console.log("Platform authenticator is available");
                }
            } catch (error) {
                console.warn("Error checking platform authenticator:", error);
            }
        }

        // 2. Try to use WebUSB to detect security keys without user interaction
        if (isWebUSBSupported()) {
            try {
                // Get list of USB devices user has already granted permission for
                const devices = await (navigator as NavigatorWithUSB).usb.getDevices();
                console.log("USB Devices with existing permissions:", devices);

                // Check if any of these devices match known security key vendors
                const securityKeys = devices.filter((device: { vendorId: number; deviceClass: number }) =>
                    FIDO_DEVICE_FILTERS.some(filter =>
                        (filter.vendorId && device.vendorId === filter.vendorId) ||
                        (filter.classCode && device.deviceClass === filter.classCode)
                    )
                );

                if (securityKeys.length > 0) {
                    console.log("Found security keys with existing permissions:", securityKeys);
                    // Store the result in localStorage for the UI to use
                    localStorage.setItem('securityKeyConnected', 'true');
                    return true;
                }

                // Note: We avoid using navigator.usb.requestDevice() as it would trigger a permission prompt
                // which would be disruptive to the user experience
            } catch (error) {
                console.warn("Error accessing USB devices:", error);
            }
        }

        // 3. As a fallback, use localStorage if we've previously detected a key
        // This means once a key is detected as connected, we'll assume it's still connected
        // until the user manually simulates disconnection or refreshes the page
        const isConnected = localStorage.getItem('securityKeyConnected') === 'true';
        return isConnected;

    } catch (error) {
        console.error('Error checking security key status:', error);
        return false; // Assume disconnected on error
    }
};

/**
 * Set security key status (for demo/manual simulation)
 */
export const setSecurityKeyStatus = (isConnected: boolean): void => {
    localStorage.setItem('securityKeyConnected', isConnected ? 'true' : 'false');

    // Dispatch storage event to notify other tabs
    try {
        const event = new StorageEvent('storage', {
            key: 'securityKeyConnected',
            newValue: isConnected ? 'true' : 'false',
            url: window.location.href
        });
        window.dispatchEvent(event);
    } catch (error) {
        console.error('Error dispatching storage event:', error);
    }
};

/**
 * Initialize security key status based on authentication method
 * Call this function after user login to set the initial state
 */
export const initializeSecurityKeyStatus = (isSecurityKeyAuth: boolean): void => {
    try {
        // Set the initial security key status in localStorage
        setSecurityKeyStatus(isSecurityKeyAuth);
        console.log(`Initialized security key status: ${isSecurityKeyAuth ? 'connected' : 'disconnected'}`);
    } catch (error) {
        console.error('Error initializing security key status:', error);
    }
};

/**
 * Request permission to access security key via WebUSB (requires user interaction)
 * This should only be called in response to a user action (like a button click)
 */
export const requestSecurityKeyAccess = async (): Promise<boolean> => {
    if (!isWebUSBSupported()) {
        console.warn('WebUSB is not supported in this browser');
        return false;
    }

    try {
        const device = await (navigator as NavigatorWithUSB).usb.requestDevice({
            filters: FIDO_DEVICE_FILTERS
        });

        console.log("Security key access granted:", device);
        localStorage.setItem('securityKeyConnected', 'true');
        return true;
    } catch (error) {
        console.warn("User cancelled device selection or no device found:", error);
        return false;
    }
};

// Handle WebAuthn registration
interface SecurityKeyDetails {
  model: string;
  type: string;
  serialNumber: string;
  pin: string;
  keyId?: number; 
}

export const registerSecurityKey = async (
    username: string,
    onSuccess: (message: string) => void,
    onError: (message: string) => void,
    keyDetails?: SecurityKeyDetails & { keyId?: number },  
    forceRegistration?: boolean  
): Promise<void> => {
    try {
        console.log('Beginning security key registration for:', username);
        console.log('Force registration:', forceRegistration ? 'Yes' : 'No');
        console.log('Key Details:', keyDetails);

        // Step 1: Begin WebAuthn registration
        const registerBeginResponse = await axios.post(`${API_URL}/webauthn/register/begin`, {
            username,
            forceRegistration,
            keyId: keyDetails?.keyId, // Pass key ID if we're updating an existing key
            ...getBindingData()
        }) as { data: { registrationToken: string, publicKey: any } };

        console.log('Registration begin response received');

        // Store the registration token
        const registrationToken = registerBeginResponse.data.registrationToken;

        // Get the options directly
        const options = registerBeginResponse.data.publicKey;

        // Step 2: Call WebAuthn browser API
        console.log('Starting registration with browser API');
        const attestation = await startRegistration(options);
        console.log('Registration response received from browser');

        // Parse clientDataJSON into an object
        const clientDataObj = JSON.parse(atob(attestation.response.clientDataJSON));

        // Fix challenge encoding
        clientDataObj.challenge = fixBase64Padding(clientDataObj.challenge);

        // Convert back to base64 for transmission
        attestation.response.clientDataJSON = btoa(JSON.stringify(clientDataObj));

        // Step 3: Complete registration on the server
        console.log('Completing registration with server');
        console.log('Including forceRegistration flag:', forceRegistration);
        console.log('Including keyId:', keyDetails?.keyId);

        const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
        const headers: Record<string, string> = {};
        if (userInfo && userInfo.authToken) {
            headers['Authorization'] = `Bearer ${userInfo.authToken}`;
        }
        
        const completeResponse = await axios.post(`${API_URL}/webauthn/register/complete`, {
            registrationToken,
            username,
            attestationResponse: attestation,
            forceRegistration,
            keyId: keyDetails?.keyId, // Pass key ID for existing keys
            ...(keyDetails || {}), // Include the security key details
            ...getBindingData()
        }, { headers }) as { data: { status: string, message?: string, error?: string, keyId?: number, keyName?: string } };

        console.log('Registration complete response:', completeResponse.data);

        if (completeResponse.data.status === 'success') {
            // Set security key status to connected after successful registration
            setSecurityKeyStatus(true);

            const successMessage = completeResponse.data.message || 'Security key registered successfully!';

            onSuccess(successMessage);
        } else {
            onError(completeResponse.data.error || 'Registration failed');
        }
    } catch (err: any) {
        console.error('WebAuthn registration error:', err);

        // Be more specific about WebAuthn errors
        if (err.name === 'NotAllowedError') {
            if (forceRegistration) {
                // For force registration, provide a different message
                onError('Registration was not allowed. Please ensure your security key is connected and try again.');
            } else {
                onError('This security key appears to be already registered to an account. Each security key can only be registered to one account for maximum security.');
            }
        } else if (err.name === 'AbortError') {
            onError('Security key registration was cancelled or timed out.');
        } else if (err.name === 'SecurityError') {
            onError('A security error occurred. Please ensure you are using a secure connection.');
        } else {
            onError(err.response?.data?.error || `Security key registration failed: ${err.message || err.name}`);
        }
    }
};


// Handle WebAuthn login after password verification
export const authenticateWithSecurityKey = async (
    username: string,
    authToken: string,
    bindingNonce: string,
    onSuccess: (userData: any) => void,
    onError: (message: string) => void,
    setRiskScore?: (score: number) => void
): Promise<void> => {
    // Reset the authentication lock if it's been more than 30 seconds
    // This prevents the lock from getting stuck if a previous authentication failed to release it
    const lastAuthTime = parseInt(sessionStorage.getItem('lastAuthAttemptTime') || '0');
    const currentTime = Date.now();

    if (currentTime - lastAuthTime > 30000) {  // 30 seconds
        console.log('Resetting stale authentication lock (more than 30 seconds old)');
        authenticationInProgress = false;
    }

    // Record the current authentication attempt time
    sessionStorage.setItem('lastAuthAttemptTime', currentTime.toString());

    // Prevent multiple simultaneous authentication attempts
    if (authenticationInProgress) {
        console.log('Authentication already in progress, ignoring duplicate request');
        onError('Authentication already in progress. Please wait a moment before trying again.');
        return;
    }

    // Set the lock before starting
    authenticationInProgress = true;
    console.log('Authentication lock acquired');

    try {
        console.log('Beginning security key authentication for:', username);

        // Make sure binding data is stored
        if (authToken && bindingNonce) {
            console.log('Storing binding data for authentication');
            storeBindingData(authToken, bindingNonce);
        } else {
            console.warn('No token or nonce provided for authentication');
        }

        // Step 1: Begin WebAuthn authentication
        console.log('Sending authentication begin request for user:', username);
        const loginBeginResponse = await axios.post<{
            publicKey: any;
            riskScore?: number;
        }>(`${API_URL}/webauthn/login/begin`, {
            username,
            secondFactor: true,
            auth_token: authToken,
            binding_nonce: bindingNonce,
            directSecurityKeyAuth: true
        });

        console.log('Authentication begin response received');

        // Get options directly
        const options = loginBeginResponse.data.publicKey;

        // Store risk score if provided and handler exists
        if (loginBeginResponse.data.riskScore !== undefined && setRiskScore) {
            setRiskScore(loginBeginResponse.data.riskScore);
        }

        // Step 2: Call WebAuthn browser API
        console.log('Starting authentication with browser API');
        const assertion = await startAuthentication(options);
        console.log('Authentication response received from browser');

        // Step 3: Complete authentication on the server
        console.log('Completing authentication with server for user:', username);
        const loginCompleteResponse = await axios.post<{
            risk_score: number;
            status: string;
            auth_token: string;
            binding_nonce: string;
            user_id: string;
            firstName: string;
            lastName: string;
            role: string;
            [key: string]: any;
        }>(`${API_URL}/webauthn/login/complete`, {
            username,  // Make sure this is the same value used in login/begin
            assertionResponse: assertion,
            secondFactor: true,
            auth_token: authToken,
            binding_nonce: bindingNonce,
            directSecurityKeyAuth: true
        });

        console.log('Authentication complete response:', loginCompleteResponse.data);

        // Store the new tokens from the server for future API calls
        if (loginCompleteResponse.data.auth_token && loginCompleteResponse.data.binding_nonce) {
            storeBindingData(
                loginCompleteResponse.data.auth_token,
                loginCompleteResponse.data.binding_nonce
            );
        }

        // Set security key status to connected after successful authentication
        setSecurityKeyStatus(true);

        // Return user data on success
        onSuccess(loginCompleteResponse.data);
    } catch (err: any) {
        console.error('WebAuthn authentication error:', err);

        // Check for axios error response first
        if (err.response && err.response.data) {
            // Handle specific backend error messages
            if (err.response.data.error) {
                const errorMessage = err.response.data.error;

                // Handle specific error cases that we want to show to the user
                if (errorMessage.includes('deactivated') || errorMessage.includes('inactive')) {
                    onError('This security key has been deactivated. Please contact your administrator.');
                } else if (errorMessage.includes('registered to another user')) {
                    onError('Login failed. Key is already registered to another user.');
                } else {
                    // Forward other backend error messages
                    onError(errorMessage);
                }
                return;
            }
        }

        // If not a backend error, handle WebAuthn-specific errors
        if (err.name === 'AbortError') {
            onError('Authentication was cancelled or timed out. Please try again and follow your browser\'s prompts.');
        } else if (err.name === 'NotAllowedError') {
            onError('Authentication was not allowed. Did you use the correct security key?');
        } else if (err.name === 'SecurityError') {
            onError('A security error occurred. Please ensure you are using a secure connection.');
        } else {
            onError(`Security key authentication failed: ${err.message || err.name}`);
        }
    } finally {
        // Always release the lock when we're done, regardless of success or failure
        authenticationInProgress = false;
        console.log('Authentication process complete, lock released');
    }
};
