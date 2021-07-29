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

var __openId = {

    init : function(opts) {
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
