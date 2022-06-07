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

const jsdom = require('jsdom');
const sdk = require('../static/js/uid2-sdk-1.0.0.js');

class CookieMock {
  constructor(document) {
    this.jar = new jsdom.CookieJar();
    this.url = document.URL;
    this.set = (value) => this.jar.setCookieSync(value, this.url, { http: false });
    this.get = () => this.jar.getCookieStringSync(this.url, { http: false });
    this.getSetCookieString = (name) => {
      return this.jar.getSetCookieStringsSync(this.url).filter(c => c.startsWith(name+'='))[0];
    };
    this.applyTo = (document) => {
      jest.spyOn(document, 'cookie', 'get').mockImplementation(() => this.get());
      jest.spyOn(document, 'cookie', 'set').mockImplementation((value) => this.set(value));
    };

    this.applyTo(document);
  }
}

class XhrMock {
  get DONE() {
    return 4;
  }

  constructor(window) {
    this.open             = jest.fn();
    this.send             = jest.fn();
    this.abort            = jest.fn();
    this.overrideMimeType = jest.fn();
    this.setRequestHeader = jest.fn();
    this.status = 200;
    this.responseText = btoa("response_text")
    this.readyState       = this.DONE;
    this.applyTo = (window) => {
      jest.spyOn(window, 'XMLHttpRequest').mockImplementation(() => this);
    };

    this.applyTo(window);
  }
}

class CryptoMock {
  static decrypt_output = "decrypted_message";
  constructor(window) {
    this.getRandomValues = jest.fn();
    this.subtle = {
      encrypt: jest.fn(),
      decrypt: jest.fn(),
      importKey: jest.fn(),
    };
    let mockDecryptResponse = jest.fn();
    mockDecryptResponse.mockImplementation((fn) => fn(CryptoMock.decrypt_output))

    this.subtle.decrypt.mockImplementation((settings, key, data) => {
      return {then: jest.fn().mockImplementation((func) => {
        console.log(settings)
        func(Buffer.concat([settings.iv, data]));
        return {catch: jest.fn()}
      })}
    });

    this.subtle.importKey.mockImplementation((format, key, algorithm, extractable, keyUsages) => {
      return {then: jest.fn().mockImplementation((func) => {
        func("key");
        return {catch: jest.fn()}
      })}
    });

    this.applyTo = (window) => {
      window.crypto = this;
    }

    this.applyTo(window);
  }

}

function setupFakeTime() {
  jest.useFakeTimers();
  jest.spyOn(global, 'setTimeout');
  jest.spyOn(global, 'clearTimeout');
  jest.setSystemTime(new Date('2021-10-01'));
}

function resetFakeTime() {
  setTimeout.mockClear();
  clearTimeout.mockClear();
  jest.clearAllTimers();
  jest.setSystemTime(new Date('2021-10-01'));
}

function setCookieMock(document) {
  return new CookieMock(document);
}

function setUid2Cookie(value) {
  document.cookie = sdk.UID2.COOKIE_NAME + '=' + encodeURIComponent(JSON.stringify(value));
}

function getUid2Cookie() {
  const docCookie = document.cookie;
  if (docCookie) {
    const payload = docCookie.split('; ').find(row => row.startsWith(sdk.UID2.COOKIE_NAME+'='));
    if (payload) {
      return JSON.parse(decodeURIComponent(payload.split('=')[1]));
    }
  }
}

function makeIdentityV1(overrides) {
  return {
     advertising_token: 'test_advertising_token',
     refresh_token: 'test_refresh_token',
     refresh_from: Date.now() + 100000,
     identity_expires: Date.now() + 200000,
     refresh_expires: Date.now() + 300000,
     ...(overrides || {}),
  };
}

function makeIdentityV2(overrides) {
  return {
    advertising_token: 'test_advertising_token',
    refresh_token: 'test_refresh_token',
    refresh_response_key: btoa('test_refresh_response_key'),
    refresh_from: Date.now() + 100000,
    identity_expires: Date.now() + 200000,
    refresh_expires: Date.now() + 300000,
    ...(overrides || {}),
  };
}
module.exports = {
  CookieMock: CookieMock,
  XhrMock: XhrMock,
  CryptoMock: CryptoMock,
  setupFakeTime: setupFakeTime,
  resetFakeTime: resetFakeTime,
  setCookieMock: setCookieMock,
  setUid2Cookie: setUid2Cookie,
  getUid2Cookie: getUid2Cookie,
  makeIdentityV1: makeIdentityV1,
  makeIdentityV2: makeIdentityV2,
};
