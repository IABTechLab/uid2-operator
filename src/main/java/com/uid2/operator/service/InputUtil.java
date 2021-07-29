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

package com.uid2.operator.service;

public class InputUtil {

    private static String GMAILDOMAIN = "gmail.com";

    public static InputVal NormalizeHash(String input) {
        final int inputLength = input.length();
        if (inputLength == 44) {
            try {
                EncodingUtils.fromBase64(input);
                return InputVal.ValidHash(input, input);
            } catch (Exception e) {
            }
        } else if (inputLength == 64) {
            try {
                final byte[] s = EncodingUtils.fromHexString(input);
                return InputVal.ValidHash(input, EncodingUtils.toBase64String(s));
            } catch (Exception e) {
            }
        }
        return InputVal.InvalidHash(input);

    }

    public static InputVal NormalizeEmail(String email) {
        final String normalize = NormalizeEmailString(email);
        if (normalize != null && normalize.length() > 0) {
            return InputVal.ValidEmail(email, normalize);
        }
        return InputVal.InvalidEmail(email);
    }

    public static String NormalizeEmailString(String email) {
        final StringBuilder preSb = new StringBuilder();
        final StringBuilder preSbSpecialized = new StringBuilder();
        final StringBuilder sb = new StringBuilder();
        StringBuilder wsBuffer = new StringBuilder();

        EmailParsingState parsingState = EmailParsingState.Starting;

        boolean inExtension = false;

        for (int i = 0; i < email.length(); ++i) {
            final char cGiven = email.charAt(i);
            final char c;

            if (cGiven >= 'A' && cGiven <= 'Z') {
                c = (char) (cGiven + 32);
            } else {
                c = cGiven;
            }

            switch (parsingState) {
                case Starting: {
                    if (c == ' ') {
                        break;
                    }
                }
                case Pre: {
                    if (c == '@') {
                        parsingState = EmailParsingState.SubDomain;
                    } else if (c == '.') {
                        preSb.append(c);
                    } else if (c == '+') {
                        preSb.append(c);
                        inExtension = true;
                    } else {
                        preSb.append(c);
                        if (!inExtension) {
                            preSbSpecialized.append(c);
                        }
                    }
                    break;
                }
                case SubDomain: {
                    if (c == '@') {
                        return null;
                    }
                    if (c == ' ') {
                        wsBuffer.append(c);
                        break;
                    }
                    if (wsBuffer.length() > 0) {
                        sb.append(wsBuffer.toString());
                        wsBuffer = new StringBuilder();
                    }
                    sb.append(c);
                }
            }
        }
        if (sb.length() == 0) {
            return null;
        }
        final String domainPart = sb.toString();

        final StringBuilder addressPartToUse;
        if (GMAILDOMAIN.equals(domainPart)) {
            addressPartToUse = preSbSpecialized;
        } else {
            addressPartToUse = preSb;
        }
        if (addressPartToUse.length() == 0) {
            return null;
        }

        return addressPartToUse.append('@').append(domainPart).toString();
    }

    public static enum Type {
        Email,
        Hash
    }

    private static enum EmailParsingState {
        Starting,
        Pre,
        SubDomain,
        Domain,
        Terminal,
    }

    public static class InputVal {
        private final String provided;
        private final String normalized;
        private final Type type;
        private final boolean valid;
        private final String identityInput;

        public InputVal(String provided, String normalized, Type type, boolean valid) {
            this.provided = provided;
            this.normalized = normalized;
            this.type = type;
            this.valid = valid;
            if (valid) {
                if (this.type == Type.Email) {
                    this.identityInput = TokenUtils.getEmailHash(this.normalized);
                } else {
                    this.identityInput = this.normalized;
                }
            } else {
                this.identityInput = null;
            }
        }

        public static InputVal ValidEmail(String input, String normalized) {
            return new InputVal(input, normalized, Type.Email, true);
        }

        public static InputVal InvalidEmail(String input) {
            return new InputVal(input, null, Type.Email, false);
        }

        public static InputVal ValidHash(String input, String normalized) {
            return new InputVal(input, normalized, Type.Hash, true);
        }

        public static InputVal InvalidHash(String input) {
            return new InputVal(input, null, Type.Hash, false);
        }

        public String getIdentityInput() {
            return this.identityInput;
        }

        public String getProvided() {
            return provided;
        }

        public String getNormalized() {
            return normalized;
        }

        public Type getType() {
            return type;
        }

        public boolean isValid() {
            return valid;
        }
    }

}
