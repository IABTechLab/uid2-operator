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

const sdk = require('../../static/js/euid-sdk-1.0.0.js');
const mocks = require('../mocks.js');
const {CryptoMock} = require("../mocks");

let callback;
let euid;
let xhrMock;
let cryptoMock;

mocks.setupFakeTime();

beforeEach(() => {
  callback = jest.fn();
  euid = new sdk.EUID();
  xhrMock = new mocks.XhrMock(sdk.window);
  cryptoMock = new mocks.CryptoMock(sdk.window);
  mocks.setCookieMock(sdk.window.document);
});

afterEach(() => {
  mocks.resetFakeTime();
});

const setEuidCookie = mocks.setEuidCookie;
const getEuidCookie = mocks.getEuidCookie;
const makeIdentityV2 = mocks.makeIdentityV2;

describe('initial state before init() is called', () => {
  it('should be in initialising state', () => {
    expect(euid).toBeInInitialisingState();
  });
});

describe('when initialising with invalid options', () => {
  it('should fail on no opts', () => {
    expect(() => euid.init()).toThrow(TypeError);
  });
  it('should fail on opts not being an object', () => {
    expect(() => euid.init(12345)).toThrow(TypeError);
  });
  it('should fail on opts being null', () => {
    expect(() => euid.init(null)).toThrow(TypeError);
  });
  it('should fail on no callback provided', () => {
    expect(() => euid.init({ })).toThrow(TypeError);
  });
  it('should fail on callback not being a function', () => {
    expect(() => euid.init({ callback: 12345 })).toThrow(TypeError);
  });
  it('should fail on refreshRetryPeriod not being a number', () => {
    expect(() => euid.init({ callback: () => {}, refreshRetryPeriod: 'abc' })).toThrow(TypeError);
  });
  it('should fail on refreshRetryPeriod being less than 1 second', () => {
    expect(() => euid.init({ callback: () => {}, refreshRetryPeriod: 1 })).toThrow(RangeError);
  });
});

describe('when called with incomplete identity', () => {

  it('error on missing advertising_token', () => {
    let identity = makeIdentityV2();
    delete identity["advertising_token"];
    euid.init({ callback: callback, identity: identity });
    expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: -2,
        statusText: "advertising_token is not available or is not valid"
    }));
  });
  it('error on missing refresh_token', () => {
    let identity = makeIdentityV2();
    delete identity["refresh_token"];
    euid.init({ callback: callback, identity: identity });
    expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
      advertisingToken: undefined,
      advertising_token: undefined,
      status: -2,
      statusText: "refresh_token is not available or is not valid"
    }));
  });
  it('error on missing refresh_from', () => {
    let identity = makeIdentityV2();
    delete identity["refresh_from"];
    euid.init({ callback: callback, identity: identity });
    expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
      advertisingToken: undefined,
      advertising_token: undefined,
      status: -2,
      statusText: "refresh_from is not available or is not valid"
    }));
  });
  it('error on missing identity_expires', () => {
    let identity = makeIdentityV2();
    delete identity["identity_expires"];
    euid.init({ callback: callback, identity: identity });
    expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
      advertisingToken: undefined,
      advertising_token: undefined,
      status: -2,
      statusText: "identity_expires is not available or is not valid"
    }));
  });
  it('error on missing refresh_expires', () => {
    let identity = makeIdentityV2();
    delete identity["refresh_expires"];
    euid.init({ callback: callback, identity: identity });
    expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
      advertisingToken: undefined,
      advertising_token: undefined,
      status: -2,
      statusText: "refresh_expires is not available or is not valid"
    }));
  });
});

test('init() should fail if called multiple times', () => {
  euid.init({ callback: () => {} });
  expect(() => euid.init({ callback: () => {} })).toThrow();
});

describe('when initialised without identity', () => {
  describe('when euid cookie is not available', () => {
    beforeEach(() => {
      euid.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.NO_IDENTITY,
      }));
    });
    it('should not set cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when euid cookie with invalid JSON is available', () => {
    beforeEach(() => {
      setEuidCookie({});
      euid.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.INVALID,
      }));
    });
    it('should clear cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when euid cookie with up-to-date identity is available v2', () => {
    const identity = makeIdentityV2();

    beforeEach(() => {
      setEuidCookie(identity);
      euid.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: identity.advertising_token,
        advertising_token: identity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(identity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(identity.advertising_token);
    });
  });

  describe('when euid cookie with expired refresh is available', () => {
    const identity = makeIdentityV2({
      refresh_expires: Date.now() - 100000
    });

    beforeEach(() => {
      setEuidCookie(identity);
      euid.init({ callback: callback });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should clear cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when euid cookie with valid but refreshable identity is available', () => {
    const identity = makeIdentityV2({
      refresh_from: Date.now() - 100000
    });

    beforeEach(() => {
      setEuidCookie(identity);
      euid.init({ callback: callback });
    });

    it('should initiate token refresh', () => {
      expect(xhrMock.send).toHaveBeenCalledTimes(1);
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in initialising state', () => {
      expect(euid).toBeInInitialisingState();
    });
  });

  describe('when euid v2 cookie with expired but refreshable identity is available', () => {
    const identity = makeIdentityV2({
      identity_expires: Date.now() - 100000,
      refresh_from: Date.now() - 100000
    });

    beforeEach(() => {
      setEuidCookie(identity);
      euid.init({ callback: callback });
    });

    it('should initiate token refresh', () => {
      expect(xhrMock.send).toHaveBeenCalledTimes(1);
      let url = "https://prod.euid.eu/v2/token/refresh";
      expect(xhrMock.open).toHaveBeenLastCalledWith("POST", url, true);
      expect(xhrMock.send).toHaveBeenLastCalledWith(identity.refresh_token);
      xhrMock.onreadystatechange();
      expect(cryptoMock.subtle.importKey).toHaveBeenCalled();
    });

    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in initialising state', () => {
      expect(euid).toBeInInitialisingState();
    });
  });
});

describe('when initialised with specific identity', () => {
  describe('when invalid identity is supplied', () => {
    beforeEach(() => {
      euid.init({ callback: callback, identity: {} });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.INVALID,
      }));
    });
    it('should clear cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when valid v2 identity is supplied', () => {
    const identity = makeIdentityV2();

    beforeEach(() => {
      euid.init({ callback: callback, identity: identity });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: identity.advertising_token,
        advertising_token: identity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(identity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(identity.advertising_token);
    });
  });

  describe('when valid identity is supplied and cookie is available', () => {
    const initIdentity = makeIdentityV2({
      advertising_token: 'init_advertising_token'
    });
    const cookieIdentity = makeIdentityV2({
      advertising_token: 'cookie_advertising_token'
    });

    beforeEach(() => {
      setEuidCookie(cookieIdentity);
      euid.init({ callback: callback, identity: initIdentity });
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: initIdentity.advertising_token,
        advertising_token: initIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(initIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(initIdentity.advertising_token);
    });
  });
});

describe('when still valid identity is refreshed on init', () => {
  const originalIdentity = makeIdentityV2({
    advertising_token: 'original_advertising_token',
    refresh_from: Date.now() - 100000
  });
  const updatedIdentity = makeIdentityV2({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    euid.init({ callback: callback, identity: originalIdentity });
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'success', body: updatedIdentity }));
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: updatedIdentity.advertising_token,
        advertising_token: updatedIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.REFRESHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(updatedIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(updatedIdentity.advertising_token);
    });
  });

  describe('when token refresh returns invalid response', () => {
    beforeEach(() => {
      xhrMock.responseText = 'abc';
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: originalIdentity.advertising_token,
        advertising_token: originalIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns optout', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'optout' }));
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.OPTOUT,
      }));
    });
    it('should not set cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns expired token', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'expired_token' });
      xhrMock.status = 400;
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should not set cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'error', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: originalIdentity.advertising_token,
        advertising_token: originalIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns no body', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success' });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: originalIdentity.advertising_token,
        advertising_token: originalIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns incorrect body type', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success', body: 5 });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: originalIdentity.advertising_token,
        advertising_token: originalIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh returns invalid body', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'success', body: {} });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: originalIdentity.advertising_token,
        advertising_token: originalIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.ESTABLISHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(originalIdentity.advertising_token);
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
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should not set cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });
});

describe('when expired identity is refreshed on init', () => {
  const originalIdentity = makeIdentityV2({
    advertising_token: 'original_advertising_token',
    refresh_from: Date.now() - 100000,
    identity_expires: Date.now() - 1
  });
  const updatedIdentity = makeIdentityV2({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    euid.init({ callback: callback, identity: originalIdentity });
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'success', body: updatedIdentity }));
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: updatedIdentity.advertising_token,
        advertising_token: updatedIdentity.advertising_token,
        status: sdk.EUID.IdentityStatus.REFRESHED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(updatedIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(euid).toBeInAvailableState(updatedIdentity.advertising_token);
    });
  });

  describe('when token refresh returns optout', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'optout' }));
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.OPTOUT,
      }));
    });
    it('should not set cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns expired token', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'expired_token' });
      xhrMock.status = 400;
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should not set cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'error', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.EXPIRED,
      }));
    });
    it('should set cookie', () => {
      expect(getEuidCookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in temporarily unavailable state', () => {
      expect(euid).toBeInTemporarilyUnavailableState();
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
        advertisingToken: undefined,
        advertising_token: undefined,
        status: sdk.EUID.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    it('should not set cookie', () => {
      expect(getEuidCookie()).toBeUndefined();
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in unavailable state', () => {
      expect(euid).toBeInUnavailableState();
    });
  });
});

describe('abort()', () => {
  it('should not clear cookie', () => {
    const identity = makeIdentityV2();
    setEuidCookie(identity);
    euid.abort();
    expect(getEuidCookie().advertising_token).toBe(identity.advertising_token);
  });
  it('should abort refresh timer', () => {
    euid.init({ callback: callback, identity: makeIdentityV2() });
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).not.toHaveBeenCalled();
    euid.abort();
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).toHaveBeenCalledTimes(1);
  });
  it('should not abort refresh timer if not timer is set', () => {
    euid.init({ callback: callback, identity: makeIdentityV2({ refresh_from: Date.now() - 100000 }) });
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
    euid.abort();
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  it('should abort refresh token request', () => {
    euid.init({ callback: callback, identity: makeIdentityV2({ refresh_from: Date.now() - 100000 }) });
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).not.toHaveBeenCalled();
    euid.abort();
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).toHaveBeenCalledTimes(1);
  });
  it('should prevent subsequent calls to init()', () => {
    euid.abort();
    expect(() => euid.init({ callback: () => {} })).toThrow();
  });
});

describe('disconnect()', () => {
  it('should clear cookie', () => {
    setEuidCookie(makeIdentityV2());
    euid.disconnect();
    expect(getEuidCookie()).toBeUndefined();
  });
  it('should abort refresh timer', () => {
    euid.init({ callback: callback, identity: makeIdentityV2() });
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).not.toHaveBeenCalled();
    euid.disconnect();
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).toHaveBeenCalledTimes(1);
  });
  it('should abort refresh token request', () => {
    euid.init({ callback: callback, identity: makeIdentityV2({ refresh_from: Date.now() - 100000 }) });
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).not.toHaveBeenCalled();
    euid.disconnect();
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
    expect(xhrMock.abort).toHaveBeenCalledTimes(1);
  });
  it('should not invoke callback after aborting refresh token request', () => {
    euid.init({ callback: callback, identity: makeIdentityV2({ refresh_from: Date.now() - 100000 }) });
    euid.disconnect();
    expect(callback).not.toHaveBeenCalled();
  });
  it('should prevent subsequent calls to init()', () => {
    euid.disconnect();
    expect(() => euid.init({ callback: () => {} })).toThrow();
  });
  it('should switch to unavailable state', () => {
    euid.init({ callback: callback, identity: makeIdentityV2() });
    euid.disconnect();
    expect(euid).toBeInUnavailableState();
  });
});
