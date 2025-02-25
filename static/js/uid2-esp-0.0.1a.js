function __esp_getUID2Async(cb) {
    const url = "https://prod.uidapi.com/ops/logSdk?host=" + document.location.origin;
    const req = new XMLHttpRequest();
    req.open("GET", url, false);
    req.setRequestHeader("X-UID2-Client-Version", "uid2-esp-0.0.1a");
    req.send();
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