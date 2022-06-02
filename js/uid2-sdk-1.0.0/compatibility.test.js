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

const setUid2Cookie = mocks.setUid2Cookie;
const getUid2Cookie = mocks.getUid2Cookie;
const makeIdentity = mocks.makeIdentityV1;

describe('when a v0 cookie is available', () => {
  const originalIdentity = {
    advertising_token: 'original_advertising_token',
    refresh_token: 'original_refresh_token',
  };
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
      setUid2Cookie(originalIdentity);
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
    it('should set enriched cookie', () => {
      expect(getUid2Cookie().refresh_token).toBe(originalIdentity.refresh_token);
      expect(getUid2Cookie().refresh_from).toBe(Date.now());
      expect(getUid2Cookie().identity_expires).toBeGreaterThan(Date.now());
      expect(getUid2Cookie().refresh_expires).toBeGreaterThan(Date.now());
      expect(getUid2Cookie().identity_expires).toBeLessThan(getUid2Cookie().refresh_expires);
    });
    it('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    it('should be in available state', () => {
      expect(uid2).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });
});
