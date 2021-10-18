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

expect.extend({
  toBeNonEmptyString(received) {
    expect(typeof received).toBe('string');
    expect(received).not.toEqual('');
    return {
      pass: true,
      message: () => 'Expected non-empty string'
    };
  }
});

expect.extend({
  toBeInInitialisingState(uid2) {
    expect(uid2.getAdvertisingToken()).toBeUndefined();
    expect(uid2.isLoginRequired()).toBeUndefined();

    return {
      pass: true,
      message: () => 'Expected getAdvertisingToken() returns undefined and isLoginRequired() returns undefined'
    };
  },

  toBeInAvailableState(uid2, expectedAdvertisingToken) {
    if (typeof expectedAdvertisingToken !== 'undefined') {
      expect(uid2.getAdvertisingToken()).toBe(expectedAdvertisingToken);
    } else if (uid2.getAdvertisingToken() !== '') {
      expect(uid2.getAdvertisingToken()).toBeNonEmptyString();
    }

    expect(uid2.isLoginRequired()).toEqual(false);

    return {
      pass: true,
      message: () => 'Expected getAdvertisingToken() returns a token and isLoginRequired() returns false'
    };
  },

  toBeInTemporarilyUnavailableState(uid2) {
    expect(uid2.getAdvertisingToken()).toBeUndefined();
    expect(uid2.isLoginRequired()).toEqual(false);

    return {
      pass: true,
      message: () => 'Expected getAdvertisingToken() returns undefined and isLoginRequired() returns false'
    };
  },

  toBeInUnavailableState(uid2) {
    expect(uid2.getAdvertisingToken()).toBeUndefined();
    expect(uid2.isLoginRequired()).toEqual(true);

    return {
      pass: true,
      message: () => 'Expected getAdvertisingToken() returns undefined and isLoginRequired() returns true'
    };
  }
});
