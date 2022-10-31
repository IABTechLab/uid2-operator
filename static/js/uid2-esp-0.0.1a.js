function __esp_getUID2Async(cb) {
    return new Promise(function(cb) {
        if (window.__uid2 && window.__uid2.getAdvertisingToken) {
            cb(__uid2.getAdvertisingToken());
        } else {
            throw new "UID2 SDK not present";
        }
    });
}

if (typeof (googletag) !== "undefined" && googletag) {

    googletag.encryptedSignalProviders.push({
        id: 'uidapi.com',
        collectorFunction: () => {
           return __esp_getUID2Async().then((signals) => signals);
        }
    });
    
}