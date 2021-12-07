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
const mocks = require('./mocks.js');

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

const setUid2Cookie = mocks.setUid2Cookie;
const getUid2Cookie = mocks.getUid2Cookie;
const makeIdentity = mocks.makeIdentity;

describe('initial state before init() is called', () => {
  it('should be in initialising state', () => {
    expect(uid2).toBeInInitialisingState();
  });
});

describe('when initialising with invalid options', () => {
  it('should fail on no opts', () => {
    expect(() => uid2.init()).toThrow(TypeError);
  });
  it('should fail on opts not being an object', () => {
    expect(() => uid2.init(12345)).toThrow(TypeError);
  });
  it('should fail on opts being null', () => {
    expect(() => uid2.init(null)).toThrow(TypeError);
  });
  it('should fail on no callback provided', () => {
    expect(() => uid2.init({ })).toThrow(TypeError);
  });
  it('should fail on callback not being a function', () => {
    expect(() => uid2.init({ callback: 12345 })).toThrow(TypeError);
  });
  it('should fail on refreshRetryPeriod not being a number', () => {
    expect(() => uid2.init({ callback: () => {}, refreshRetryPeriod: 'abc' })).toThrow(TypeError);
  });
  it('should fail on refreshRetryPeriod being less than 1 second', () => {
    expect(() => uid2.init({ callback: () => {}, refreshRetryPeriod: 1 })).toThrow(RangeError);
  });
});

test('init() should fail if called multiple times', () => {
  uid2.init({ callback: () => {} });
  expect(() => uid2.init({ callback: () => {} })).toThrow();
});

describe('when initialised without identity', () => {
  describe('when uid2 cookie is not available', () => {
    beforeEach(() => {
      uid2.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.NO_IDENTITY,
      }));
    });
    it('should not set cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when uid2 cookie with invalid JSON is available', () => {
    beforeEach(() => {
      setUid2Cookie({});
      uid2.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.INVALID,
      }));
    });
    it('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when uid2 cookie with up-to-date identity is available', () => {
    const identity = makeIdentity({});

    beforeEach(() => {
      setUid2Cookie(identity);
      uid2.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: identity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(identity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(identity.advertising_token);
    });
  });

  describe('when uid2 cookie with expired refresh is available', () => {
    const identity = makeIdentity({
      refresh_expires: Date.now() - 100000
    });

    beforeEach(() => {
      setUid2Cookie(identity);
      uid2.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when uid2 cookie with valid but refreshable identity is available', () => {
    const identity = makeIdentity({
      refresh_from: Date.now() - 100000
    });

    beforeEach(() => {
      setUid2Cookie(identity);
      uid2.init({ callback: callback });
    });

    it('should initiate token refresh', () => {
      expect(xhrMock.send).toHaveBeenCalledTimes(1);
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in initialising state', () => {
      expect(uid2).toBeInInitialisingState();
    });
  });

  describe('when uid2 cookie with expired but refreshable identity is available', () => {
    const identity = makeIdentity({
      identity_expires: Date.now() - 100000,
      refresh_from: Date.now() - 100000
    });

    beforeEach(() => {
      setUid2Cookie(identity);
      uid2.init({ callback: callback });
    });

    it('should initiate token refresh', () => {
      expect(xhrMock.send).toHaveBeenCalledTimes(1);
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in initialising state', () => {
      expect(uid2).toBeInInitialisingState();
    });
  });
});

describe('when initialised with specific identity', () => {
  describe('when invalid identity is supplied', () => {
    beforeEach(() => {
      uid2.init({ callback: callback, identity: {} });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.INVALID,
      }));
    });
    it('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when valid identity is supplied', () => {
    const identity = makeIdentity({});

    beforeEach(() => {
      uid2.init({ callback: callback, identity: identity });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: identity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(identity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(identity.advertising_token);
    });
  });

  describe('when valid identity is supplied and cookie is available', () => {
    const initIdentity = makeIdentity({
      advertising_token: 'init_advertising_token'
    });
    const cookieIdentity = makeIdentity({
      advertising_token: 'cookie_advertising_token'
    });

    beforeEach(() => {
      setUid2Cookie(cookieIdentity);
      uid2.init({ callback: callback, identity: initIdentity });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: initIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(initIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(initIdentity.advertising_token);
    });
  });
});

describe('when still valid identity is refreshed on init', () => {
  const originalIdentity = makeIdentity({
    advertising_token: 'original_advertising_token',
    refresh_from: Date.now() - 100000
  });
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    uid2.init({ callback: callback, identity: originalIdentity });
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: updatedIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.REFRESHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(updatedIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(updatedIdentity.advertising_token);
    });
  });

  describe('when token refresh returns invalid response', () => {
    beforeEach(() => {
      xhrMock.responseText = 'abc';
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: originalIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns optout', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'optout' });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.OPTOUT,
      }));
    });
    it('should not set cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'error', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: originalIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns no body', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success' });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: originalIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns incorrect body type', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success', body: 5 });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: originalIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns invalid body', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success', body: {} });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: originalIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh fails and current identity expires', () => {
    beforeEach(() => {
      jest.setSystemTime(originalIdentity.refresh_expires * 1000 + 1);
      xhrMock.responseText = JSON.stringify({ status: 'error' });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should not set cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });
});

describe('when expired identity is refreshed on init', () => {
  const originalIdentity = makeIdentity({
    advertising_token: 'original_advertising_token',
    refresh_from: Date.now() - 100000,
    identity_expires: Date.now() - 1
  });
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    uid2.init({ callback: callback, identity: originalIdentity });
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: updatedIdentity.advertising_token,
        status: sdk.UID2.IdentityStatus.REFRESHED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(updatedIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(updatedIdentity.advertising_token);
    });
  });

  describe('when token refresh returns optout', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'optout' });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.OPTOUT,
      }));
    });
    it('should not set cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'error', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.EXPIRED,
      }));
    });
    it('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in temporarily unavailable state', () => {
      expect(uid2).toBeInTemporarilyUnavailableState();
    });
  });

  describe('when token refresh fails and current identity expires', () => {
    beforeEach(() => {
      jest.setSystemTime(originalIdentity.refresh_expires * 1000 + 1);
      xhrMock.responseText = JSON.stringify({ status: 'error' });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertising_token: undefined,
        status: sdk.UID2.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should not set cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });
});

describe('abort()', () => {
  it('should not clear cookie', () => {
    const identity = makeIdentity();
    setUid2Cookie(identity);
    uid2.abort();
    expect(getUid2Cookie().advertising_token).toBe(identity.advertising_token);
  });
  it('should abort refresh timer', () => {
    uid2.init({ callback: callback, identity: makeIdentity() });
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).not.toHaveBeenCalled();
    uid2.abort();
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).toHaveBeenCalledTimes(1);
  });
  it('should not abort refresh timer if not timer is set', () => {
    uid2.init({ callback: callback, identity: makeIdentity({ refresh_from: Date.now() - 100000 }) });
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
    uid2.abort();
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  it('should abort refresh token request', () => {
    uid2.init({ callback: callback, identity: makeIdentity({ refresh_from: Date.now() - 100000 }) });
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).not.toHaveBeenCalled();
    uid2.abort();
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).toHaveBeenCalledTimes(1);
  });
  it('should prevent subsequent calls to init()', () => {
    uid2.abort();
    expect(() => uid2.init({ callback: () => {} })).toThrow();
  });
});

describe('disconnect()', () => {
  it('should clear cookie', () => {
    setUid2Cookie(makeIdentity());
    uid2.disconnect();
    expect(getUid2Cookie()).toBeUndefined();
  });
  it('should abort refresh timer', () => {
    uid2.init({ callback: callback, identity: makeIdentity() });
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).not.toHaveBeenCalled();
    uid2.disconnect();
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).toHaveBeenCalledTimes(1);
  });
  it('should abort refresh token request', () => {
    uid2.init({ callback: callback, identity: makeIdentity({ refresh_from: Date.now() - 100000 }) });
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).not.toHaveBeenCalled();
    uid2.disconnect();
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).toHaveBeenCalledTimes(1);
  });
  it('should prevent subsequent calls to init()', () => {
    uid2.disconnect();
    expect(() => uid2.init({ callback: () => {} })).toThrow();
  });
});
