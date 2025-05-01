import axios from 'axios';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { toast } from 'sonner';
import { API_URL } from "@/app/utils/constants";

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

// Extend the Navigator interface to include the 'usb' property
interface NavigatorWithUSB extends Navigator {
    usb: {
        requestDevice: (options: { filters: any[] }) => Promise<any>;
    };
}
export const isWebUSBSupported = (): boolean => {
    return window &&
        'usb' in navigator &&
        typeof (navigator as NavigatorWithUSB).usb.requestDevice === 'function';
};


/**
 * Initialize security key status based on authentication method
 * Call this function after user login to set the initial state
 */
export const initializeSecurityKeyStatus = (isSecurityKeyAuth: boolean): void => {
    try {
        // Set the initial security key status in localStorage
        localStorage.setItem('securityKeyConnected', isSecurityKeyAuth ? 'true' : 'false');
        console.log(`Initialized security key status: ${isSecurityKeyAuth ? 'connected' : 'disconnected'}`);
    } catch (error) {
        console.error('Error initializing security key status:', error);
    }
};

/**
 * Checks if a security key is currently connected using a silent WebAuthn challenge
 * This uses a real challenge-response to verify the key without user interaction
 */
export const checkSecurityKeyStatus = async (username: string): Promise<boolean> => {
    // First check if WebAuthn is supported by the browser
    if (!isWebUSBSupported()) {
        console.warn('WebAuthn is not supported in this browser');
        return false;
    }

    // For debugging mode or development, we can use the Alt+K simulation
    // Return the stored value without making an actual check
    if (process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_USE_DEMO_KEY_MODE === 'true') {
        console.log('Using demo mode for security key status check');
        return localStorage.getItem('securityKeyConnected') === 'true';
    }

    try {
        console.log('Checking security key status with real WebAuthn challenge');

        // Step 1: Request a silent challenge from the server
        const checkResponse = await axios.post(`${API_URL}/api/webauthn/check-status`, {
            username,
            ...getBindingData()
        });

        const responseData = checkResponse.data as { publicKey?: any, challengeId?: string };

        if (!responseData.publicKey) {
            console.warn('No challenge received for security key status check');
            return false;
        }

        // Extract the challenge and challenge ID
        const options = (checkResponse.data as { publicKey: any }).publicKey;
        const challengeId = (checkResponse.data as { challengeId: string }).challengeId;

        // Step 2: Try to perform a silent authentication
        try {
            console.log('Attempting silent WebAuthn authentication');

            // Set a timeout of 5 seconds for the silent check
            const timeoutPromise = new Promise<never>((_, reject) => {
                setTimeout(() => reject(new Error('Security key check timed out')), 5000);
            });

            // Try to get the credential silently without user interaction
            // We use true as the second parameter to indicate we want silent authentication if possible
            const authPromise = startAuthentication(options);

            // Race between the authentication and timeout
            const assertion = await Promise.race([authPromise, timeoutPromise]);

            // Step 3: Complete verification on the server
            console.log('Authentication successful, sending to server for verification');
            const completeResponse = await axios.post(`${API_URL}/api/webauthn/check-status/complete`, {
                username,
                assertionResponse: assertion,
                challengeId
            });

            console.log('Server verification response:', completeResponse.data);

            // If we get here, the key is connected and verified
            const isConnected = (completeResponse.data as { isConnected: boolean }).isConnected === true;

            // Update localStorage to reflect the key's status
            localStorage.setItem('securityKeyConnected', isConnected ? 'true' : 'false');

            // Notify other tabs via storage event
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

            return isConnected;
        } catch (error) {
            // If we get here, either the key isn't connected or it couldn't be accessed silently
            console.warn('Security key not accessible or not connected:', error);

            // Update localStorage to reflect disconnected status
            localStorage.setItem('securityKeyConnected', 'false');

            // Notify other tabs
            try {
                const event = new StorageEvent('storage', {
                    key: 'securityKeyConnected',
                    newValue: 'false',
                    url: window.location.href
                });
                window.dispatchEvent(event);
            } catch (error) {
                console.error('Error dispatching storage event:', error);
            }

            return false;
        }
    } catch (error) {
        console.error('Error in checkSecurityKeyStatus:', error);
        return false;
    }
};

// Handle WebAuthn registration
export const registerSecurityKey = async (
    username: string,
    onSuccess: (message: string) => void,
    onError: (message: string) => void
): Promise<void> => {
    try {
        console.log('Beginning security key registration for:', username);

        // Step 1: Begin WebAuthn registration
        const registerBeginResponse = await axios.post(`${API_URL}/webauthn/register/begin`, {
            username,
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
        const completeResponse = await axios.post(`${API_URL}/webauthn/register/complete`, {
            registrationToken,
            username,
            attestationResponse: attestation,
            ...getBindingData()
        }) as { data: { status: string, message?: string, error?: string } };

        console.log('Registration complete response:', completeResponse.data);

        if (completeResponse.data.status === 'success') {
            // Set security key status to connected after successful registration
            localStorage.setItem('securityKeyConnected', 'true');

            // Notify other tabs
            try {
                const event = new StorageEvent('storage', {
                    key: 'securityKeyConnected',
                    newValue: 'true',
                    url: window.location.href
                });
                window.dispatchEvent(event);
            } catch (error) {
                console.error('Error dispatching storage event:', error);
            }

            onSuccess(completeResponse.data.message || 'Security key registered successfully!');
        } else {
            onError(completeResponse.data.error || 'Registration failed');
        }
    } catch (err: any) {
        console.error('WebAuthn registration error:', err);

        // Be more specific about WebAuthn errors
        if (err.name === 'NotAllowedError') {
            onError('This security key appears to be already registered to an account. Each security key can only be registered to one account for maximum security.');
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
    onError: (message: string) => void
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

        // Update security key status
        localStorage.setItem('securityKeyConnected', 'true');

        // Notify other tabs
        try {
            const event = new StorageEvent('storage', {
                key: 'securityKeyConnected',
                newValue: 'true',
                url: window.location.href
            });
            window.dispatchEvent(event);
        } catch (error) {
            console.error('Error dispatching storage event:', error);
        }

        // Return user data on success
        onSuccess(loginCompleteResponse.data);
    } catch (err: any) {
        console.error('WebAuthn authentication error:', err);

        // Handle WebAuthn-specific errors
        if (err.name === 'AbortError') {
            onError('Authentication was cancelled or timed out. Please try again and follow your browser\'s prompts.');
        } else if (err.name === 'NotAllowedError') {
            onError('Authentication was not allowed. Did you use the correct security key?');
        } else if (err.name === 'SecurityError') {
            onError('A security error occurred. Please ensure you are using a secure connection.');
        } else if (err.response?.data?.error) {
            onError(err.response.data.error);
        } else {
            onError(`Security key authentication failed: ${err.message || err.name}`);
        }
    } finally {
        // Always release the lock when we're done, regardless of success or failure
        authenticationInProgress = false;
        console.log('Authentication process complete, lock released');
    }
};
