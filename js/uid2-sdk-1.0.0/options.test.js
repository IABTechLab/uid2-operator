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

const sdk = require('../../static/js/uid2-sdk-1.0.0.js');
const mocks = require('../mocks.js');

let callback;
let uid2;
let xhrMock;
let cookieMock;

mocks.setupFakeTime();

const mockDomain = 'www.uidapi.com';
const mockUrl = `http://${mockDomain}/test/index.html`;

beforeEach(() => {
  callback = jest.fn();
  uid2 = new sdk.UID2();
  xhrMock = new mocks.XhrMock(sdk.window);
  jest.spyOn(document, 'URL', 'get').mockImplementation(() => mockUrl);
  cookieMock = new mocks.CookieMock(sdk.window.document);
});

afterEach(() => {
  mocks.resetFakeTime();
});

const makeIdentity = mocks.makeIdentityV1;

describe('cookieDomain option', () => {
  describe('when using default value', () => {
    beforeEach(() => {
      uid2.init({ callback: callback, identity: makeIdentity() });
    });

    it('should not mention domain in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.UID2.COOKIE_NAME);
      expect(cookie).not.toBe('');
      expect(cookie).not.toContain('Domain=');
    });
  });

  describe('when using custom value', () => {
    const domain = 'uidapi.com';

    beforeEach(() => {
      uid2.init({ callback: callback, identity: makeIdentity(), cookieDomain: domain });
    });

    it('should use domain in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.UID2.COOKIE_NAME);
      expect(cookie).toContain(`Domain=${domain};`);
    });
  });
});

describe('cookiePath option', () => {
  describe('when using default value', () => {
    beforeEach(() => {
      uid2.init({ callback: callback, identity: makeIdentity() });
    });

    it('should use the default path in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.UID2.COOKIE_NAME);
      expect(cookie+';').toContain('Path=/;');
    });
  });

  describe('when using custom value', () => {
    const path = '/test/';

    beforeEach(() => {
      uid2.init({ callback: callback, identity: makeIdentity(), cookiePath: path });
    });

    it('should use custom path in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.UID2.COOKIE_NAME);
      expect(cookie+';').toContain(`Path=${path};`);
    });
  });
});

describe('baseUrl option', () => {
  const identity = makeIdentity({
    refresh_from: Date.now()- 100000
  });

  describe('when using default value', () => {
    beforeEach(() => {
      uid2.init({ callback: callback, identity: identity });
    });

    it('should use prod URL when refreshing token', () => {
      expect(xhrMock.open.mock.calls.length).toBe(1);
      expect(xhrMock.open.mock.calls[0][1]).toContain('prod.uidapi.com');
    });
  });

  describe('when using custom value', () => {
    const baseUrl = 'http://test-host';

    beforeEach(() => {
      uid2.init({ callback: callback, identity: identity, baseUrl: baseUrl });
    });

    it('should use custom URL when refreshing token', () => {
      expect(xhrMock.open.mock.calls.length).toBe(1);
      expect(xhrMock.open.mock.calls[0][1]).not.toContain('prod.uidapi.com');
      expect(xhrMock.open.mock.calls[0][1]).toContain('test-host');
    });
  });
});

describe('refreshRetryPeriod option', () => {
  describe('when using default value', () => {
    beforeEach(() => {
      uid2.init({ callback: callback, identity: makeIdentity() });
    });

    it('it should use the default retry period', () => {
      expect(setTimeout.mock.calls.length).toBe(1);
      expect(setTimeout.mock.calls[0][1]).toBe(sdk.UID2.DEFAULT_REFRESH_RETRY_PERIOD_MS);
    });
  });

  describe('when using custom value', () => {
    beforeEach(() => {
      uid2.init({ callback: callback, identity: makeIdentity(), refreshRetryPeriod: 12345 });
    });

    it('it should use the default retry period', () => {
      expect(setTimeout.mock.calls.length).toBe(1);
      expect(setTimeout.mock.calls[0][1]).toBe(12345);
    });
  });
});
