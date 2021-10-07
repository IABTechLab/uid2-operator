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

function __esp_getUID2Async(cb) {
    return new Promise(function(cb) {
        if (window.__uid2 && window.__uid2.getAdvertisingToken) {
            cb(__uid2.getAdvertisingToken());
        } else {
            throw new "UID2 SDK not present";
        }
    });
}

if (googletag) {

    googletag.encryptedSignalProviders.push({
        id: 'uidapi.com',
        collectorFunction: () => {
           return __esp_getUID2Async().then((signals) => signals);
        }
    });
    
}

class UID2 {
    constructor() {
        this.init = (opts) => {
            const identity = opts["identity"];
            if (identity) {
                this.setIdentity(identity);
            }
            else {
                this.refreshIfNeeded();
            }
        };
        this.refreshIfNeeded = () => {
            const identity = this.getIdentity();
            if (identity) {
                const url = "https://prod.uidapi.com/token/refresh?refresh_token=" + encodeURIComponent(identity["refresh_token"]);
                const req = new XMLHttpRequest();
                req.overrideMimeType("application/json");
                var cb = this.handleRefreshResponse;
                req.open("GET", url, false);
                req.onload = function () {
                    cb(req.responseText);
                };
                req.send();
            }
        };
        this.handleRefreshResponse = (body) => {
            this.setIdentity(body);
        };
        this.getIdentity = () => {
            const payload = this.getCookie("__uid_2");
            if (payload) {
                return JSON.parse(payload);
            }
        };
        this.getAdvertisingToken = () => {
            const identity = this.getIdentity();
            if (identity) {
                return identity["advertisement_token"];
            }
        };
        this.setIdentity = (value) => {
            var payload;
            if (typeof (value) === "object") {
                payload = JSON.stringify(value);
            }
            else {
                payload = value;
            }
            this.setCookie("__uid_2", payload);
        };
        this.setCookie = (name, value) => {
            var days = 7;
            var date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            document.cookie = name + "=" + encodeURIComponent(value) + " ;path=/;expires=" + date.toUTCString();
        };
        this.getCookie = (name) => {
            const docCookie = document.cookie;
            if (docCookie) {
                var payload = docCookie.split('; ').find(row => row.startsWith(name));
                if (payload) {
                    return decodeURIComponent(payload.split('=')[1]);
                }
            }
            else {
                return undefined;
            }
        };
        this.removeCookie = (name) => {
            document.cookie = name + "=;path=/;expires=Tue, 1 Jan 1980 23:59:59 GMT";
        };
        this.disconnect = () => {
            this.removeCookie("__uid_2");
        };
    }
}
window.__uid2 = new UID2();
