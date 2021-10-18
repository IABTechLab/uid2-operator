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
let document;
let xhrMock;
let cookieMock;

mocks.setupFakeTime();

beforeEach(() => {
  callback = jest.fn();
  uid2 = new sdk.UID2();
  xhrMock = new mocks.XhrMock(sdk.window);
  document = sdk.window.document;
  cookieMock = new mocks.CookieMock(document);
});

afterEach(() => {
  mocks.resetFakeTime();
});

const setUid2Cookie = mocks.setUid2Cookie;
const getUid2Cookie = mocks.getUid2Cookie;
const makeIdentity = mocks.makeIdentity;

describe('when auto refreshing a non-expired identity which does not require a refresh', () => {
  beforeEach(() => {
    uid2.init({callback: callback, identity: makeIdentity({})});
    jest.clearAllMocks();
    jest.runOnlyPendingTimers();
  });

  it('should not invoke the callback', () => {
    expect(callback.mock.calls.length).toBe(0);
  });
  it('should not initiate token refresh', () => {
    expect(xhrMock.send).not.toHaveBeenCalled();
  });
  it('should set refresh timer', () => {
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  it('should be in available state', () => {
    expect(uid2).toBeInAvailableState();
  });
});

describe('when auto refreshing a non-expired identity which requires a refresh', () => {
  const refreshFrom = Date.now() + 100;
  const originalIdentity = makeIdentity({
    advertising_token: 'original_advertising_token',
    refresh_from: refreshFrom
  });
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    uid2.init({callback: callback, identity: originalIdentity});
    jest.clearAllMocks();
    jest.setSystemTime(refreshFrom);
    jest.runOnlyPendingTimers();
  });

  it('should not invoke the callback', () => {
    expect(callback.mock.calls.length).toBe(0);
  });
  it('should initiate token refresh', () => {
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
  });
  it('should not set refresh timer', () => {
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  it('should be in available state', () => {
    expect(uid2).toBeInAvailableState();
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({status: 'success', body: updatedIdentity});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(1);
      expect(callback.mock.calls[0][0].advertising_token).toBe(updatedIdentity.advertising_token);
      expect(callback.mock.calls[0][0].status).toBe(sdk.UID2.IdentityStatus.REFRESHED);
    });
    it('should set cookie', () => {
      expect(document.cookie).not.toBe('');
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
      xhrMock.responseText = JSON.stringify({status: 'optout'});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(1);
      expect(callback.mock.calls[0][0].advertising_token).toBeUndefined();
      expect(callback.mock.calls[0][0].status).toBe(sdk.UID2.IdentityStatus.OPTOUT);
    });
    it('should clear cookie', () => {
      expect(document.cookie).toBe('');
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({status: 'error', body: updatedIdentity});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should not invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(0);
    });
    it('should not update cookie', () => {
      expect(document.cookie).not.toBe('');
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
      xhrMock.responseText = JSON.stringify({status: 'error'});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(1);
      expect(callback.mock.calls[0][0].advertising_token).toBeUndefined();
      expect(callback.mock.calls[0][0].status).toBe(sdk.UID2.IdentityStatus.REFRESH_EXPIRED);
    });
    it('should clear cookie', () => {
      expect(document.cookie).toBe('');
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });
});

describe('when auto refreshing an expired identity', () => {
  const refreshFrom = Date.now() + 100;
  const originalIdentity = makeIdentity({
    advertising_token: 'original_advertising_token',
    identity_expires: refreshFrom,
    refresh_from: refreshFrom
  });
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    uid2.init({callback: callback, identity: originalIdentity});
    jest.clearAllMocks();
    jest.setSystemTime(refreshFrom);
    jest.runOnlyPendingTimers();
  });

  it('should not invoke the callback', () => {
    expect(callback.mock.calls.length).toBe(0);
  });
  it('should initiate token refresh', () => {
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
  });
  it('should not set refresh timer', () => {
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  it('should be in available state', () => {
    expect(uid2).toBeInAvailableState();
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({status: 'success', body: updatedIdentity});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(1);
      expect(callback.mock.calls[0][0].advertising_token).toBe(updatedIdentity.advertising_token);
      expect(callback.mock.calls[0][0].status).toBe(sdk.UID2.IdentityStatus.REFRESHED);
    });
    it('should set cookie', () => {
      expect(document.cookie).not.toBe('');
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
      xhrMock.responseText = JSON.stringify({status: 'optout'});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(1);
      expect(callback.mock.calls[0][0].advertising_token).toBeUndefined();
      expect(callback.mock.calls[0][0].status).toBe(sdk.UID2.IdentityStatus.OPTOUT);
    });
    it('should clear cookie', () => {
      expect(document.cookie).toBe('');
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({status: 'error', body: updatedIdentity});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(1);
      expect(callback.mock.calls[0][0].advertising_token).toBeUndefined();
      expect(callback.mock.calls[0][0].status).toBe(sdk.UID2.IdentityStatus.EXPIRED);
    });
    it('should not update cookie', () => {
      expect(document.cookie).not.toBe('');
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in temporarily unavailable state', () => {
      expect(uid2).toBeInTemporarilyUnavailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh fails and current identity expires', () => {
    beforeEach(() => {
      jest.setSystemTime(originalIdentity.refresh_expires * 1000 + 1);
      xhrMock.responseText = JSON.stringify({status: 'error'});
      xhrMock.onreadystatechange(new Event(''));
    });

    it('should invoke the callback', () => {
      expect(callback.mock.calls.length).toBe(1);
      expect(callback.mock.calls[0][0].advertising_token).toBeUndefined();
      expect(callback.mock.calls[0][0].status).toBe(sdk.UID2.IdentityStatus.REFRESH_EXPIRED);
    });
    it('should clear cookie', () => {
      expect(document.cookie).toBe('');
    });
    it('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    it('should be in unavailable state', () => {
      expect(uid2).toBeInUnavailableState();
    });
  });
});
