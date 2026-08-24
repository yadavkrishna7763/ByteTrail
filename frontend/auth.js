/**
 * ByteTrail — Reusable Authentication & Session Management Module
 * Production multi-page support
 */

const getApiBaseUrl = () => {
    if (typeof window !== "undefined") {
        if (window.BYTETRAIL_BACKEND_URL && window.BYTETRAIL_BACKEND_URL.startsWith("http")) {
            return window.BYTETRAIL_BACKEND_URL.replace(/\/+$/, "");
        }
        if (window.localStorage && window.localStorage.getItem("BYTETRAIL_API_BASE")) {
            return window.localStorage.getItem("BYTETRAIL_API_BASE").replace(/\/+$/, "");
        }
        if (window.location && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")) {
            return `${window.location.protocol}//${window.location.hostname}:8000`;
        }
    }
    return "";
};

const AUTH_API_BASE = getApiBaseUrl();

// Token and User Helpers
function getAuthToken() {
    try {
        return localStorage.getItem("bytetrail_jwt_token");
    } catch {
        return null;
    }
}

function getAuthUser() {
    try {
        const raw = localStorage.getItem("bytetrail_user");
        return raw ? JSON.parse(raw) : null;
    } catch {
        return null;
    }
}

function setAuthSession(token, user) {
    try {
        localStorage.setItem("bytetrail_jwt_token", token);
        localStorage.setItem("bytetrail_user", JSON.stringify(user));
    } catch (e) {
        console.error("Storage error:", e);
    }
}

function clearAuthSession() {
    try {
        localStorage.removeItem("bytetrail_jwt_token");
        localStorage.removeItem("bytetrail_user");
    } catch (e) {
        console.error("Storage clear error:", e);
    }
}

function getAuthHeaders(extraHeaders = {}) {
    const token = getAuthToken();
    const headers = { ...extraHeaders };
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
}

// Authentication Guards for Protected / Guest Pages
function requireAuth(redirectUrl = "login.html") {
    const token = getAuthToken();
    if (!token) {
        const currentPath = window.location.pathname.split("/").pop() || "dashboard.html";
        window.location.href = `${redirectUrl}?redirect=${encodeURIComponent(currentPath)}`;
        return false;
    }
    return true;
}

function redirectIfAuthenticated(destinationUrl = "dashboard.html") {
    const token = getAuthToken();
    if (token) {
        window.location.href = destinationUrl;
        return true;
    }
    return false;
}

// Auth API Calls
async function executeLogin(email, password) {
    const res = await fetch(`${AUTH_API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim().lower ? email.trim().toLowerCase() : email.trim(), password })
    });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || "Authentication failed");
    }
    setAuthSession(data.access_token, data.user);
    return data;
}

async function executeRegister(full_name, email, password, role = "analyst") {
    const res = await fetch(`${AUTH_API_BASE}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            full_name: full_name.trim(),
            email: email.trim().toLowerCase ? email.trim().toLowerCase() : email.trim(),
            password,
            role
        })
    });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || "Registration failed");
    }
    setAuthSession(data.access_token, data.user);
    return data;
}

async function executeDemoLogin() {
    const res = await fetch(`${AUTH_API_BASE}/api/auth/demo-login`, {
        method: "POST"
    });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || "Administrator authentication failed");
    }
    setAuthSession(data.access_token, data.user);
    return data;
}

async function executeGoogleSignIn(email = null, full_name = null, access_token = null) {
    const res = await fetch(`${AUTH_API_BASE}/api/auth/google/signin`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, full_name, access_token })
    });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.detail || "Google authentication failed");
    }
    setAuthSession(data.access_token, data.user);
    return data;
}

async function openGoogleOAuthPopup(purpose = "login") {
    try {
        const res = await fetch(`${AUTH_API_BASE}/api/v1/auth/google/url?purpose=${purpose}`);
        const data = await res.json();
        if (!res.ok || !data.url) {
            throw new Error(data.detail || "Google sign-in is not available right now");
        }
        const authUrl = data.url;

        const width = 520;
        const height = 650;
        const left = window.screen.width / 2 - width / 2;
        const top = window.screen.height / 2 - height / 2;

        const popup = window.open(
            authUrl,
            "ByteTrailGoogleAuth",
            `toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=yes, copyhistory=no, width=${width}, height=${height}, top=${top}, left=${left}`
        );
        // A blocked popup should not leave the user on a spinner forever.
        if (!popup) {
            window.location.assign(authUrl);
        }
        return popup;
    } catch (e) {
        console.error("Could not open Google OAuth:", e);
        throw e;
    }
}
