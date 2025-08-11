const sdk = require('../../static/js/euid-sdk-1.0.0.js');
const mocks = require('../mocks.js');

let callback;
let euid;
let xhrMock;
let cookieMock;

mocks.setupFakeTime();

const mockDomain = 'prod.euid.eu';
const mockUrl = `http://${mockDomain}/test/index.html`;

beforeEach(() => {
  callback = jest.fn();
  euid = new sdk.EUID();
  xhrMock = new mocks.XhrMock(sdk.window);
  jest.spyOn(document, 'URL', 'get').mockImplementation(() => mockUrl);
  cookieMock = new mocks.CookieMock(sdk.window.document);
});

afterEach(() => {
  mocks.resetFakeTime();
});

const makeIdentity = mocks.makeIdentityV2;

describe('cookieDomain option', () => {
  describe('when using default value', () => {
    beforeEach(() => {
      euid.init({ callback: callback, identity: makeIdentity() });
    });

    it('should not mention domain in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.EUID.COOKIE_NAME);
      expect(cookie).not.toBe('');
      expect(cookie).not.toContain('Domain=');
    });
  });

  describe('when using custom value', () => {
    const domain = 'euid.eu';

    beforeEach(() => {
      euid.init({ callback: callback, identity: makeIdentity(), cookieDomain: domain });
    });

    it('should use domain in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.EUID.COOKIE_NAME);
      expect(cookie).toContain(`Domain=${domain};`);
    });
  });
});

describe('cookiePath option', () => {
  describe('when using default value', () => {
    beforeEach(() => {
      euid.init({ callback: callback, identity: makeIdentity() });
    });

    it('should use the default path in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.EUID.COOKIE_NAME);
      expect(cookie+';').toContain('Path=/;');
    });
  });

  describe('when using custom value', () => {
    const path = '/test/';

    beforeEach(() => {
      euid.init({ callback: callback, identity: makeIdentity(), cookiePath: path });
    });

    it('should use custom path in the cookie string', () => {
      const cookie = cookieMock.getSetCookieString(sdk.EUID.COOKIE_NAME);
      expect(cookie+';').toContain(`Path=${path};`);
    });
  });
});

describe('baseUrl option', () => {
  const identity = makeIdentity({
    refresh_from: Date.now() - 100000
  });

  describe('when using default value', () => {
    beforeEach(() => {
      euid.init({ callback: callback, identity: identity });
    });

    it('should use prod URL when refreshing token', () => {
      expect(xhrMock.open.mock.calls.length).toBe(1);
      expect(xhrMock.open.mock.calls[0][1]).toContain('prod.euid.eu');
    });
  });

  describe('when using custom value', () => {
    const baseUrl = 'http://test-host';

    beforeEach(() => {
      euid.init({ callback: callback, identity: identity, baseUrl: baseUrl });
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
      euid.init({ callback: callback, identity: makeIdentity() });
    });

    it('it should use the default retry period', () => {
      expect(setTimeout.mock.calls.length).toBe(1);
      expect(setTimeout.mock.calls[0][1]).toBe(sdk.EUID.DEFAULT_REFRESH_RETRY_PERIOD_MS);
    });
  });

  describe('when using custom value', () => {
    beforeEach(() => {
      euid.init({ callback: callback, identity: makeIdentity(), refreshRetryPeriod: 12345 });
    });

    it('it should use the default retry period', () => {
      expect(setTimeout.mock.calls.length).toBe(1);
      expect(setTimeout.mock.calls[0][1]).toBe(12345);
    });
  });
});
