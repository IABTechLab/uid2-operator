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
    if (expectedAdvertisingToken) {
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
