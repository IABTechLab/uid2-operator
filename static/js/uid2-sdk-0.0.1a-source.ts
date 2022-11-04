class UID2 {



    public init = (opts : object) => {
        const identity = opts["identity"];
        if (identity) {
            this.setIdentity(identity);
        } else {
            this.refreshIfNeeded();
        }

    }

    public refreshIfNeeded = () => {

        const identity = this.getIdentity();
        if (identity) {
            const url = "https://prod.uidapi.com/token/refresh?refresh_token="+encodeURIComponent(identity["refresh_token"]);
            const req = new XMLHttpRequest();
            req.overrideMimeType("application/json");
            var cb = this.handleRefreshResponse;
            req.open("GET", url, false);
            req.onload = function() {
                cb(req.responseText);
            }
            req.send();



        }
    }

    private handleRefreshResponse = (body: string) => {
        this.setIdentity(body);
    }

    public getIdentity = () => {
        const payload = this.getCookie("__uid_2");
        if (payload) {
            return JSON.parse(payload);
        }
    }

    public getAdvertisingToken = () => {
        const identity = this.getIdentity();
        if (identity) {
            return identity["advertisement_token"];
        }
    }

    public setIdentity = (value: object) => {
        var payload;
        if (typeof(value) === "object") {
            payload = JSON.stringify(value);
        } else {
            payload = value;
        }
        this.setCookie("__uid_2", payload);

    }

    public setCookie = (name: string, value: string) => {
        var days = 7;
        var date = new Date();
        date.setTime(date.getTime()+(days*24*60*60*1000));

        document.cookie=name + "=" + encodeURIComponent(value) +" ;path=/;expires="+date.toUTCString();


    }
    public getCookie = (name: string) => {
        const docCookie = document.cookie;
        if (docCookie) {
            var payload = docCookie.split('; ').find(row => row.startsWith(name));
            if (payload) {
                return decodeURIComponent(payload.split('=')[1])
            }
        } else {
            return undefined;
        }
    }

    public removeCookie = (name: string) => {
        document.cookie=name+"=;path=/;expires=Tue, 1 Jan 1980 23:59:59 GMT";
    }

    public disconnect = () {
    this.removeCookie("__uid_2");
}


}

window.__uid2 = new UID2();


