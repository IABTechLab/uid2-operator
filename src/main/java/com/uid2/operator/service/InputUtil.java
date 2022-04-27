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

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;
import com.uid2.operator.model.UserIdentity;

import java.time.Instant;

public class InputUtil {

    private static String GMAILDOMAIN = "gmail.com";

    private static int MIN_PHONENUMBER_DIGITS = 10;
    private static int MAX_PHONENUMBER_DIGITS = 15;

    public static InputVal NormalizeEmailHash(String input) {
        final int inputLength = input.length();
        if (inputLength == 44) {
            try {
                EncodingUtils.fromBase64(input);
                return InputVal.ValidEmailHash(input, input);
            } catch (Exception e) {
            }
        } else if (inputLength == 64) {
            try {
                final byte[] s = EncodingUtils.fromHexString(input);
                return InputVal.ValidEmailHash(input, EncodingUtils.toBase64String(s));
            } catch (Exception e) {
            }
        }
        return InputVal.InvalidEmailHash(input);
    }

    public static InputVal NormalizePhoneHash(String input) {
        final int inputLength = input.length();
        if (inputLength == 44) {
            try {
                EncodingUtils.fromBase64(input);
                return InputVal.ValidPhoneHash(input, input);
            } catch (Exception e) {
            }
        } else if (inputLength == 64) {
            try {
                final byte[] s = EncodingUtils.fromHexString(input);
                return InputVal.ValidPhoneHash(input, EncodingUtils.toBase64String(s));
            } catch (Exception e) {
            }
        }
        return InputVal.InvalidPhoneHash(input);
    }

    public static boolean IsAsciiDigit(char d)
    {
        return d >= '0' && d <= '9';
    }

    public static boolean IsPhoneNumberNormalized(String phonenumber) {
        // normalized phonenumber must follow ITU E.164 standard, see https://www.wikipedia.com/en/E.164
        if (phonenumber == null || phonenumber.length() < MIN_PHONENUMBER_DIGITS)
            return false;

        // first character must be '+' sign
        if ('+' != phonenumber.charAt(0))
            return false;

        // count the digits, return false if non-digit charracter is found
        int totalDigits = 0;
        for (int i = 1; i < phonenumber.length(); ++i)
        {
            if (!InputUtil.IsAsciiDigit(phonenumber.charAt(i)))
                return false;
            ++totalDigits;
        }

        if (totalDigits < MIN_PHONENUMBER_DIGITS || totalDigits > MAX_PHONENUMBER_DIGITS)
            return false;

        return true;
    }

    public static InputVal NormalizeEmail(String email) {
        final String normalize = NormalizeEmailString(email);
        if (normalize != null && normalize.length() > 0) {
            return InputVal.ValidEmail(email, normalize);
        }
        return InputVal.InvalidEmail(email);
    }

    public static InputVal NormalizePhone(String phone) {
        if (IsPhoneNumberNormalized(phone)) {
            return InputVal.ValidEmail(phone, phone);
        }
        return InputVal.InvalidPhone(phone);
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

    public enum IdentityInputType {
        Raw,
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
        private final IdentityType identityType;
        private final IdentityInputType inputType;
        private final boolean valid;
        private final byte[] identityInput;

        public InputVal(String provided, String normalized, IdentityType identityType, IdentityInputType inputType, boolean valid) {
            this.provided = provided;
            this.normalized = normalized;
            this.identityType = identityType;
            this.inputType = inputType;
            this.valid = valid;
            if (valid) {
                if (this.inputType == IdentityInputType.Raw) {
                    this.identityInput = TokenUtils.getIdentityHash(this.normalized);
                } else {
                    this.identityInput = EncodingUtils.fromBase64(this.normalized);
                }
            } else {
                this.identityInput = null;
            }
        }

        public static InputVal ValidEmail(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Email, IdentityInputType.Raw, true);
        }

        public static InputVal InvalidEmail(String input) {
            return new InputVal(input, null, IdentityType.Email, IdentityInputType.Raw, false);
        }

        public static InputVal ValidEmailHash(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Email, IdentityInputType.Hash, true);
        }

        public static InputVal InvalidEmailHash(String input) {
            return new InputVal(input, null, IdentityType.Email, IdentityInputType.Hash, false);
        }

        public static InputVal ValidPhone(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Phone, IdentityInputType.Raw, true);
        }

        public static InputVal InvalidPhone(String input) {
            return new InputVal(input, null, IdentityType.Phone, IdentityInputType.Raw, false);
        }

        public static InputVal ValidPhoneHash(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Phone, IdentityInputType.Hash, true);
        }

        public static InputVal InvalidPhoneHash(String input) {
            return new InputVal(input, null, IdentityType.Phone, IdentityInputType.Hash, false);
        }

        public byte[] getIdentityInput() {
            return this.identityInput;
        }

        public String getProvided() {
            return provided;
        }

        public String getNormalized() {
            return normalized;
        }

        public IdentityType getIdentityType() {
            return identityType;
        }

        public IdentityInputType getInputType() { return inputType; }

        public boolean isValid() {
            return valid;
        }

        public UserIdentity toUserIdentity(IdentityScope identityScope, int privacyBits, Instant establishedAt) {
            return new UserIdentity(
                    identityScope,
                    this.identityType,
                    getIdentityInput(),
                    privacyBits,
                    establishedAt,
                    establishedAt);
        }
    }

}
