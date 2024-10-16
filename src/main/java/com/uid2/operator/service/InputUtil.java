package com.uid2.operator.service;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;
import com.uid2.operator.model.userIdentity.HashedDiiIdentity;

import java.time.Instant;

public class InputUtil {

    private static String GMAILDOMAIN = "gmail.com";

    private static int MIN_PHONENUMBER_DIGITS = 10;
    private static int MAX_PHONENUMBER_DIGITS = 15;

    public static InputVal normalizeEmailHash(String input) {
        final int inputLength = input.length();
        if (inputLength == 44) {
            try {
                EncodingUtils.fromBase64(input);
                return InputVal.validEmailHash(input, input);
            } catch (Exception e) {
            }
        } else if (inputLength == 64) {
            try {
                final byte[] s = EncodingUtils.fromHexString(input);
                return InputVal.validEmailHash(input, EncodingUtils.toBase64String(s));
            } catch (Exception e) {
            }
        }
        return InputVal.invalidEmailHash(input);
    }

    public static InputVal normalizePhoneHash(String input) {
        final int inputLength = input.length();
        if (inputLength == 44) {
            try {
                EncodingUtils.fromBase64(input);
                return InputVal.validPhoneHash(input, input);
            } catch (Exception e) {
            }
        } else if (inputLength == 64) {
            try {
                final byte[] s = EncodingUtils.fromHexString(input);
                return InputVal.validPhoneHash(input, EncodingUtils.toBase64String(s));
            } catch (Exception e) {
            }
        }
        return InputVal.invalidPhoneHash(input);
    }

    public static boolean isAsciiDigit(char d)
    {
        return d >= '0' && d <= '9';
    }

    public static boolean isPhoneNumberNormalized(String phoneNumber) {
        // normalized phoneNumber must follow ITU E.164 standard, see https://www.wikipedia.com/en/E.164
        if (phoneNumber == null || phoneNumber.length() < MIN_PHONENUMBER_DIGITS)
            return false;

        // first character must be '+' sign
        if ('+' != phoneNumber.charAt(0))
            return false;

        // count the digits, return false if non-digit character is found
        int totalDigits = 0;
        for (int i = 1; i < phoneNumber.length(); ++i)
        {
            if (!InputUtil.isAsciiDigit(phoneNumber.charAt(i)))
                return false;
            ++totalDigits;
        }

        if (totalDigits < MIN_PHONENUMBER_DIGITS || totalDigits > MAX_PHONENUMBER_DIGITS)
            return false;

        return true;
    }

    public static InputVal normalizeEmail(String email) {
        final String normalize = normalizeEmailString(email);
        if (normalize != null && normalize.length() > 0) {
            return InputVal.validEmail(email, normalize);
        }
        return InputVal.invalidEmail(email);
    }

    public static InputVal normalizePhone(String phone) {
        if (isPhoneNumberNormalized(phone)) {
            return InputVal.validPhone(phone, phone);
        }
        return InputVal.invalidPhone(phone);
    }

    public static String normalizeEmailString(String email) {
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

        public static InputVal validEmail(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Email, IdentityInputType.Raw, true);
        }

        public static InputVal invalidEmail(String input) {
            return new InputVal(input, null, IdentityType.Email, IdentityInputType.Raw, false);
        }

        public static InputVal validEmailHash(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Email, IdentityInputType.Hash, true);
        }

        public static InputVal invalidEmailHash(String input) {
            return new InputVal(input, null, IdentityType.Email, IdentityInputType.Hash, false);
        }

        public static InputVal validPhone(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Phone, IdentityInputType.Raw, true);
        }

        public static InputVal invalidPhone(String input) {
            return new InputVal(input, null, IdentityType.Phone, IdentityInputType.Raw, false);
        }

        public static InputVal validPhoneHash(String input, String normalized) {
            return new InputVal(input, normalized, IdentityType.Phone, IdentityInputType.Hash, true);
        }

        public static InputVal invalidPhoneHash(String input) {
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

        public HashedDiiIdentity toHashedDiiIdentity(IdentityScope identityScope, int privacyBits, Instant establishedAt) {
            return new HashedDiiIdentity(
                    identityScope,
                    this.identityType,
                    getIdentityInput(),
                    privacyBits,
                    establishedAt);
        }
    }

}
