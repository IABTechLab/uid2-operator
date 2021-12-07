// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

if (window.googletag) {
    googletag.encryptedSignalProviders.push({
        id: 'uidapi.com',
        collectorFunction: () => {
            if (window.__uid2 && window.__uid2.getAdvertisingToken) {
                return __uid2.getAdvertisingTokenAsync();
            } else {
                return Promise.reject(new Error("UID2 SDK not present"));
            }
        }
    });
}

class UID2 {
    static get VERSION() {
        return "1.0.0";
    }
    static get COOKIE_NAME() {
        return "__uid_2";
    }
    static get DEFAULT_REFRESH_RETRY_PERIOD_MS() {
        return 5000;
    }

    constructor() {
        // PUBLIC METHODS

        this.init = (opts) => {
            if (_initCalled) {
                throw new TypeError('Calling init() more than once is not allowed');
            }

            if (typeof opts !== 'object' || opts === null) {
                throw new TypeError('opts must be an object');
            } else if (typeof opts.callback !== 'function') {
                throw new TypeError('opts.callback must be a function');
            } else if (typeof opts.refreshRetryPeriod !== 'undefined') {
                if (typeof opts.refreshRetryPeriod !== 'number')
                    throw new TypeError('opts.refreshRetryPeriod must be a number');
                else if (opts.refreshRetryPeriod < 1000)
                    throw new RangeError('opts.refreshRetryPeriod must be >= 1000');
            }

            _initCalled = true;
            _opts = opts;
            applyIdentity(_opts.identity ? _opts.identity : loadIdentity());
        };
        this.getAdvertisingToken = () => {
            return _identity && !temporarilyUnavailable() ? _identity.advertising_token : undefined;
        };
        this.getAdvertisingTokenAsync = () => {
            if (!initialised()) {
                return new Promise((resolve, reject) => {
                    _promises.push({ resolve: resolve, reject: reject });
                });
            } else if (_identity) {
                return temporarilyUnavailable()
                    ? Promise.reject(new Error('temporarily unavailable'))
                    : Promise.resolve(_identity.advertising_token);
            } else {
                return Promise.reject(new Error('identity not available'));
            }
        };
        this.isLoginRequired = () => {
            return initialised() ? !_identity : undefined;
        };
        this.disconnect = () => {
            this.abort();
            removeCookie(UID2.COOKIE_NAME);
        };
        this.abort = () => {
            _initCalled = true;
            if (typeof _refreshTimerId !== 'undefined') {
                clearTimeout(_refreshTimerId);
                _refreshTimerId = undefined;
            }
            if (_refreshReq) {
                _refreshReq.abort();
                _refreshReq = undefined;
            }
        };

        // PRIVATE STATE

        let _initCalled = false;
        let _opts;
        let _identity;
        let _lastStatus;
        let _refreshTimerId;
        let _refreshReq;
        let _promises = [];

        // PRIVATE METHODS

        const initialised = () => typeof _lastStatus !== 'undefined';
        const temporarilyUnavailable = () => _lastStatus === UID2.IdentityStatus.EXPIRED;

        const getOptionOrDefault = (value, defaultValue) => {
            return typeof value === 'undefined' ? defaultValue : value;
        };

        const setCookie = (name, identity) => {
            const value = JSON.stringify(identity);
            const expires = new Date(identity.refresh_expires);
            const path = getOptionOrDefault(_opts.cookiePath, "/");
            let cookie = name + "=" + encodeURIComponent(value) + " ;path=" + path + ";expires=" + expires.toUTCString();
            if (typeof _opts.cookieDomain !== 'undefined') {
                cookie += ";domain=" + _opts.cookieDomain;
            }
            document.cookie = cookie;
        };
        const removeCookie = (name) => {
            document.cookie = name + "=;expires=Tue, 1 Jan 1980 23:59:59 GMT";
        };
        const getCookie = (name) => {
            const docCookie = document.cookie;
            if (docCookie) {
                const payload = docCookie.split('; ').find(row => row.startsWith(name+'='));
                if (payload) {
                    return decodeURIComponent(payload.split('=')[1]);
                }
            }
        };

        const updateStatus = (status, statusText) => {
            _lastStatus = status;

            const promises = _promises;
            _promises = [];

            const advertisingToken = this.getAdvertisingToken();

            const result = {
                advertising_token: advertisingToken,
                status: status,
                statusText: statusText
            };
            _opts.callback(result);

            if (advertisingToken) {
                promises.forEach(p => p.resolve(advertisingToken));
            } else {
                promises.forEach(p => p.reject(new Error(statusText)));
            }
        };
        const setValidIdentity = (identity, status, statusText) => {
            _identity = identity;
            setCookie(UID2.COOKIE_NAME, identity);
            setRefreshTimer();
            updateStatus(status, statusText);
        };
        const setFailedIdentity = (status, statusText) => {
            _identity = undefined;
            this.abort();
            removeCookie(UID2.COOKIE_NAME);
            updateStatus(status, statusText);
        };
        const checkIdentity = (identity) => {
            if (!identity.advertising_token) {
                throw new InvalidIdentityError("advertising_token is not available or is not valid");
            } else if (!identity.refresh_token) {
                throw new InvalidIdentityError("refresh_token is not available or is not valid");
            }
        };
        const tryCheckIdentity = (identity) => {
            try {
                checkIdentity(identity);
                return true;
            } catch (err) {
                if (err instanceof InvalidIdentityError) {
                    setFailedIdentity(UID2.IdentityStatus.INVALID, err.message);
                    return false;
                } else {
                    throw err;
                }
            }
        };
        const setIdentity = (identity, status, statusText) => {
          if (tryCheckIdentity(identity)) {
            setValidIdentity(identity, status, statusText);
          }
        };
        const loadIdentity = () => {
            const payload = getCookie(UID2.COOKIE_NAME);
            if (payload) {
                return JSON.parse(payload);
            }
        };

        const enrichIdentity = (identity, now) => {
            return {
                refresh_from: now,
                refresh_expires: now + 7 * 86400 * 1000, // 7 days
                identity_expires: now + 4 * 3600 * 1000, // 4 hours
                ...identity,
            };
        };
        const applyIdentity = (identity) => {
            if (!identity) {
                setFailedIdentity(UID2.IdentityStatus.NO_IDENTITY, "Identity not available");
                return;
            }

            if (!tryCheckIdentity(identity)) {
                // failed identity already set
                return;
            }

            const now = Date.now();
            identity = enrichIdentity(identity, now);
            if (identity.refresh_expires < now) {
                setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Identity expired, refresh expired");
                return;
            }
            if (identity.refresh_from <= now) {
                refreshToken(identity);
                return;
            }

            if (typeof _identity === 'undefined') {
                setIdentity(identity, UID2.IdentityStatus.ESTABLISHED, "Identity established");
            } else if (identity.advertising_token !== _identity.advertising_token) {
                // identity must have been refreshed from another tab
                setIdentity(identity, UID2.IdentityStatus.REFRESH, "Identity refreshed");
            } else {
                setRefreshTimer();
            }
        }
        const refreshToken = (identity) => {
            const baseUrl = getOptionOrDefault(_opts.baseUrl, "https://prod.uidapi.com");
            const url = baseUrl + "/v1/token/refresh?refresh_token=" + encodeURIComponent(identity.refresh_token);
            const req = new XMLHttpRequest();
            _refreshReq = req;
            req.overrideMimeType("application/json");
            req.open("GET", url, true);
            req.setRequestHeader('X-UID2-Client-Version', 'uid2-sdk-' + UID2.VERSION);
            req.onreadystatechange = () => {
                _refreshReq = undefined;
                if (req.readyState !== req.DONE) return;
                try {
                    const response = JSON.parse(req.responseText);
                    if (!checkResponseStatus(identity, response)) return;
                    checkIdentity(response.body);
                    setIdentity(response.body, UID2.IdentityStatus.REFRESHED, "Identity refreshed");
                } catch (err) {
                    handleRefreshFailure(identity, err.message);
                }
            };
            req.send();
        };
        const checkResponseStatus = (identity, response) => {
            if (typeof response !== 'object' || response === null) {
                throw new TypeError("refresh response is not an object");
            }
            if (response.status === "optout") {
                setFailedIdentity(UID2.IdentityStatus.OPTOUT, "User opted out");
                return false;
            } else if (response.status === "success") {
                if (typeof response.body === 'object' && response.body !== null) {
                  return true;
                }
                throw new TypeError("refresh response object does not have a body");
            } else {
                throw new TypeError("unexpected response status: " + response.status);
            }
        };
        const handleRefreshFailure = (identity, errorMessage) => {
            const now = Date.now();
            if (identity.refresh_expires <= now) {
                setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Refresh expired; token refresh failed: " + errorMessage);
            } else if (identity.identity_expires <= now && !temporarilyUnavailable()) {
                setValidIdentity(identity, UID2.IdentityStatus.EXPIRED, "Token refresh failed for expired identity: " + errorMessage);
            } else if (initialised()) {
                setRefreshTimer(); // silently retry later
            } else {
                setIdentity(identity, UID2.IdentityStatus.ESTABLISHED, "Identity established; token refresh failed: " + errorMessage)
            }
        };
        const setRefreshTimer = () => {
            const timeout = getOptionOrDefault(_opts.refreshRetryPeriod, UID2.DEFAULT_REFRESH_RETRY_PERIOD_MS);
            _refreshTimerId = setTimeout(() => {
                if (this.isLoginRequired()) return;
                applyIdentity(loadIdentity());
            }, timeout);
        };

        // PRIVATE ERRORS

        class InvalidIdentityError extends Error {
            constructor(message) {
                super(message);
                this.name = "InvalidIdentityError";
            }
        }
    }
}

(function (UID2) {
    let IdentityStatus; // enum
    (function (IdentityStatus) {
        // identity available
        IdentityStatus[IdentityStatus["ESTABLISHED"] = 0] = "ESTABLISHED";
        IdentityStatus[IdentityStatus["REFRESHED"] = 1] = "REFRESHED";
        // identity temporarily not available
        IdentityStatus[IdentityStatus["EXPIRED"] = 100] = "EXPIRED";
        // identity not available
        IdentityStatus[IdentityStatus["NO_IDENTITY"] = -1] = "NO_IDENTITY";
        IdentityStatus[IdentityStatus["INVALID"] = -2] = "INVALID";
        IdentityStatus[IdentityStatus["REFRESH_EXPIRED"] = -3] = "REFRESH_EXPIRED";
        IdentityStatus[IdentityStatus["OPTOUT"] = -4] = "OPTOUT";
    })(IdentityStatus = UID2.IdentityStatus || (UID2.IdentityStatus = {}));
})(UID2 || (UID2 = {}));

window.__uid2 = new UID2();

if (typeof exports !== 'undefined') {
  exports.UID2 = UID2;
  exports.window = window;
}
