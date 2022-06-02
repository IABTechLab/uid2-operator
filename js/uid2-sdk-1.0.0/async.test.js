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

mocks.setupFakeTime();

beforeEach(() => {
  callback = jest.fn();
  uid2 = new sdk.UID2();
  xhrMock = new mocks.XhrMock(sdk.window);
  mocks.setCookieMock(sdk.window.document);
});

afterEach(() => {
  mocks.resetFakeTime();
});

const makeIdentity = mocks.makeIdentityV1;

describe('when getAdvertisingTokenAsync is called before init', () => {
  describe('when initialising with a valid identity', () => {
    const identity = makeIdentity();
    it('it should resolve promise after invoking the callback', () => {
      const p = uid2.getAdvertisingTokenAsync().then(token => {
        expect(callback).toHaveBeenCalled();
        return token;
      });
      uid2.init({ callback: callback, identity: identity });
      return expect(p).resolves.toBe(identity.advertising_token);
    });
  });

  describe('when initialising with an invalid identity', () => {
    it('it should reject promise after invoking the callback', () => {
      const p = uid2.getAdvertisingTokenAsync().catch(e => {
        expect(callback).toHaveBeenCalled();
        throw e;
      });
      uid2.init({ callback: callback });
      return expect(p).rejects.toBeInstanceOf(Error);
    });
  });

  describe('when auto refresh fails due to optout', () => {
    it('it should reject promise after invoking the callback', () => {
      const originalIdentity = makeIdentity({
        refresh_from: Date.now() - 100000,
      });
      const p = uid2.getAdvertisingTokenAsync().catch(e => {
        expect(callback).toHaveBeenCalled();
        throw e;
      });
      uid2.init({ callback: callback, identity: originalIdentity });
      xhrMock.responseText = JSON.stringify({ status: 'optout' });
      xhrMock.onreadystatechange(new Event(''));
      return expect(p).rejects.toBeInstanceOf(Error);
    });
  });

  describe('when auto refresh fails, but identity still valid', () => {
    it('it should reject promise after invoking the callback', () => {
      const originalIdentity = makeIdentity({
        refresh_from: Date.now() - 100000,
      });
      const p = uid2.getAdvertisingTokenAsync().then(token => {
        expect(callback).toHaveBeenCalled();
        return token;
      });
      uid2.init({ callback: callback, identity: originalIdentity });
      xhrMock.responseText = JSON.stringify({ status: 'error' });
      xhrMock.onreadystatechange(new Event(''));
      return expect(p).resolves.toBe(originalIdentity.advertising_token);
    });
  });

  describe('when auto refresh fails, but identity already expired', () => {
    it('it should reject promise after invoking the callback', () => {
      const originalIdentity = makeIdentity({
        refresh_from: Date.now() - 100000,
        identity_expires: Date.now() - 1
      });
      const p = uid2.getAdvertisingTokenAsync().catch(e => {
        expect(callback).toHaveBeenCalled();
        throw e;
      });
      uid2.init({ callback: callback, identity: originalIdentity });
      xhrMock.responseText = JSON.stringify({ status: 'error' });
      xhrMock.onreadystatechange(new Event(''));
      return expect(p).rejects.toBeInstanceOf(Error);
    });
  });

  describe('when giving multiple promises', () => {
    const identity = makeIdentity();
    it('it should resolve all promises', () => {
      const p1 = uid2.getAdvertisingTokenAsync();
      const p2 = uid2.getAdvertisingTokenAsync();
      const p3 = uid2.getAdvertisingTokenAsync();
      uid2.init({ callback: callback, identity: identity });
      return expect(Promise.all([p1, p2, p3])).resolves.toStrictEqual(Array(3).fill(identity.advertising_token));
    });
  });
});

describe('when getAdvertisingTokenAsync is called after init completed', () => {
  describe('when initialised with a valid identity', () => {
    const identity = makeIdentity();
    it('it should resolve promise', () => {
      uid2.init({ callback: callback, identity: identity });
      return expect(uid2.getAdvertisingTokenAsync()).resolves.toBe(identity.advertising_token);
    });
  });

  describe('when initialisation failed', () => {
    it('it should reject promise', () => {
      uid2.init({ callback: callback });
      return expect(uid2.getAdvertisingTokenAsync()).rejects.toBeInstanceOf(Error);
    });
  });

  describe('when identity is temporarily not available', () => {
    it('it should reject promise', () => {
      const originalIdentity = makeIdentity({
        refresh_from: Date.now() - 100000,
        identity_expires: Date.now() - 1
      });
      uid2.init({ callback: callback, identity: originalIdentity });
      xhrMock.responseText = JSON.stringify({ status: 'error' });
      xhrMock.onreadystatechange(new Event(''));
      return expect(uid2.getAdvertisingTokenAsync()).rejects.toBeInstanceOf(Error);
    });
  });

  describe('when disconnect() has been called', () => {
    it('it should reject promise', () => {
      uid2.init({ callback: callback, identity: makeIdentity() });
      uid2.disconnect();
      return expect(uid2.getAdvertisingTokenAsync()).rejects.toBeInstanceOf(Error);
    });
  });
});

describe('when getAdvertisingTokenAsync is called before refresh on init completes', () => {
  const originalIdentity = makeIdentity({
    refresh_from: Date.now() - 100000,
  });
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    uid2.init({ callback: callback, identity: originalIdentity });
  });

  describe('when auto refresh completes successfully', () => {
    it('it should resolve promise after invoking the callback', () => {
      const p = uid2.getAdvertisingTokenAsync().then(token => {
        expect(callback).toHaveBeenCalled();
        return token;
      });
      xhrMock.responseText = JSON.stringify({ status: 'success', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
      return expect(p).resolves.toBe(updatedIdentity.advertising_token);
    });
  });

  describe('when disconnect() has been called', () => {
    it('it should reject promise', () => {
      const p = uid2.getAdvertisingTokenAsync();
      uid2.disconnect();
      return expect(p).rejects.toBeInstanceOf(Error);
    });
  });

  describe('when promise obtained after disconnect', () => {
    it('it should reject promise', () => {
      uid2.disconnect();
      return expect(uid2.getAdvertisingTokenAsync()).rejects.toBeInstanceOf(Error);
    });
  });
});
