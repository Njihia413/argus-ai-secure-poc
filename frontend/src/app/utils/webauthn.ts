import axios from 'axios';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { toast } from 'sonner';
import {API_URL} from "@/app/utils/constants";

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
        });

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
        });

        console.log('Registration complete response:', completeResponse.data);

        if (completeResponse.data.status === 'success') {
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
        console.log('Sending authentication begin request with secondFactor=true');

        const loginBeginResponse = await axios.post(`${API_URL}/webauthn/login/begin`, {
            username,
            secondFactor: true,  // This is important for MFA
            ...getBindingData()  // Should now include the stored auth_token and binding_nonce
        });

        console.log('Authentication begin response received');

        // Get options directly
        const options = loginBeginResponse.data.publicKey;

        // Step 2: Call WebAuthn browser API
        console.log('Starting authentication with browser API');
        const assertion = await startAuthentication(options);
        console.log('Authentication response received from browser');

        // Step 3: Complete authentication on the server
        console.log('Completing authentication with server (secondFactor=true)');
        const loginCompleteResponse = await axios.post(`${API_URL}/webauthn/login/complete`, {
            username,
            assertionResponse: assertion,
            secondFactor: true,  // This is important for MFA
            ...getBindingData()  // Should include the auth_token and binding_nonce
        });

        console.log('Authentication complete response:', loginCompleteResponse.data);

        // Handle risk score if provided
        const riskScore = loginCompleteResponse.data.risk_score;
        if (riskScore > 75) {
            toast.warning("High-risk login detected. Additional monitoring is in place.");
        } else if (riskScore > 40) {
            toast.info("Login from unusual location or device detected.");
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
