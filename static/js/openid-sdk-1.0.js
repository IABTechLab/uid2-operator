var __openId = {

    init : function(opts) {
        const url = "https://prod.uidapi.com/ops/logSdk?host=" + document.location.origin;
        const req = new XMLHttpRequest();
        req.open("GET", url, false);
        req.setRequestHeader("X-UID2-Client-Version", "openid-sdk-1.0");
        req.send();

        this.opts = opts;
        if (!this.opts["events"]) {
            this.opts["events"] = {}
        }
        if (this.opts["events"]["init"]) {
            this.printDebug("Calling init callback");
            this.opts["events"]["init"](this);
        }
        if (this.opts["start"]) {
            if (this.opts["identity"]) {
                this.setIdentity(this.opts["identity"]);
            } else if (this.opts["email"]) {
                this.startVerificationFlow();
            } else {
                if (!this.detectFromUrl()) {
                    this.refreshIfNeededIdentity();
                    return;
                }
            }

            this.establishIdentity();
        }

    },

    getTDID : function() {
        var cookie = Cookies.get("__open_id")
        if (cookie) {
            var payload = JSON.parse(decodeURIComponent(cookie));
            return payload["tdid"];
        }
    },

    detectFromUrl : function() {
        const urlParams = new URLSearchParams(window.location.search);
        const payload = urlParams.get("__oidt");
        console.log("Payload = ");
        console.log(payload);

        if (payload && payload != "") {
            this.setIdentity(payload);
            return true;
        } else {
            return false;
        }
    },

    sendCode : function() {

        $("#verification-entry").show();

    },
    verifyCode: function() {

        console.log("Submit Value");

        var email = this.opts["email"];
        var setIdentitfy = this.setIdentity;
        var establish = this.establishIdentity;

        $.ajax({
            url: "https://www.openid2.com:444/identity/verification/submit?email="+email+
            "&privacy_bits=1&code=1234&token=abasca",
        })
            .done(function( data ) {
                var d = JSON.stringify(data);

                window.__openId.opts["identity"] = d;
                window.__openId.setIdentity();
                window.__openId.establishIdentity();
            });

    },
    startVerificationFlow : function() {
        $("#open-id-container").show();
        $("#verification-email").val(this.opts["email"]);
        $("#send-code").on("click", this.sendCode);
        $("#verify-code").on("click", function() { window.__openId.verifyCode() });
    },

    setIdentity : function(tokens) {
        Cookies.set("__open_id", tokens);
    },


    establishIdentity : function() {
        var cookie = Cookies.get("__open_id")
        if (cookie) {
            var payload = JSON.parse(decodeURIComponent(cookie));
            console.log("Cookie Payload = ");
            console.log(cookie);
            this.opts["events"]["established"](payload["advertisement_token"]);
        } else {
            console.log("here");
            if (this.opts["events"]["not_established"]) {
                this.opts["events"]["not_established"]();
            }
        }
    },

    disconnect : function() {
        Cookies.remove("__open_id");
        this.establishIdentity();
    },

    needsRereshing : function(paylod) {
        var refreshToken = paylod["refresh_token"];
        // FIXME TODO check for Reresh and continue the Lifecycle
        return true;
    },

    refreshIfNeededIdentity : function() {
        var cookie = Cookies.get("__open_id")
        if (cookie) {
            var payload = JSON.parse(decodeURIComponent(cookie));
            console.log("Cookie Payload = ");
            console.log(cookie);
            if (this.needsRereshing(payload)) {

                $.ajax({
                    url: "https://www.openid2.com:444/token/refresh?refresh_token="+encodeURIComponent(payload["refresh_token"])
                })
                    .done(function( data ) {
                        console.log("Token = ");
                        console.log(data);
                        if (data && data["advertisement_token"] && data["advertisement_token"] != "") {
                            var d = encodeURIComponent(JSON.stringify(data));
                            window.__openId.setIdentity(d);
                        } else {
                            window.__openId.disconnect();
                        }
                        window.__openId.establishIdentity();
                    });
            }
        } else {
            window.__openId.establishIdentity();
        }
        this.printDebug("Reresh Token here");
    },

    printDebug : function(m) {
        console.log("__open_id: " + m);

    }
}
window.__openId = __openId;
console.log("OepnID SDK Loaded");
