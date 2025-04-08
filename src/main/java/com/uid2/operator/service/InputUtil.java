package com.uid2.operator.service;

import com.uid2.operator.model.identities.IdentityScope;
import com.uid2.operator.model.identities.DiiType;
import com.uid2.operator.model.identities.HashedDii;

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

    public enum DiiInputType {
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
        //Directly Identifying Information (DII) (email or phone) see https://unifiedid.com/docs/ref-info/glossary-uid#gl-dii
        private final DiiType diiType;
        private final DiiInputType inputType;
        private final boolean valid;
        private final byte[] diiInput;

        public InputVal(String provided, String normalized, DiiType diiType, DiiInputType inputType, boolean valid) {
            this.provided = provided;
            this.normalized = normalized;
            this.diiType = diiType;
            this.inputType = inputType;
            this.valid = valid;
            if (valid) {
                if (this.inputType == DiiInputType.Raw) {
                    this.diiInput = TokenUtils.getHashedDii(this.normalized);
                } else {
                    this.diiInput = EncodingUtils.fromBase64(this.normalized);
                }
            } else {
                this.diiInput = null;
            }
        }

        public static InputVal validEmail(String input, String normalized) {
            return new InputVal(input, normalized, DiiType.Email, DiiInputType.Raw, true);
        }

        public static InputVal invalidEmail(String input) {
            return new InputVal(input, null, DiiType.Email, DiiInputType.Raw, false);
        }

        public static InputVal validEmailHash(String input, String normalized) {
            return new InputVal(input, normalized, DiiType.Email, DiiInputType.Hash, true);
        }

        public static InputVal invalidEmailHash(String input) {
            return new InputVal(input, null, DiiType.Email, DiiInputType.Hash, false);
        }

        public static InputVal validPhone(String input, String normalized) {
            return new InputVal(input, normalized, DiiType.Phone, DiiInputType.Raw, true);
        }

        public static InputVal invalidPhone(String input) {
            return new InputVal(input, null, DiiType.Phone, DiiInputType.Raw, false);
        }

        public static InputVal validPhoneHash(String input, String normalized) {
            return new InputVal(input, normalized, DiiType.Phone, DiiInputType.Hash, true);
        }

        public static InputVal invalidPhoneHash(String input) {
            return new InputVal(input, null, DiiType.Phone, DiiInputType.Hash, false);
        }

        public byte[] getHashedDiiInput() {
            return this.diiInput;
        }

        public String getProvided() {
            return provided;
        }

        public String getNormalized() {
            return normalized;
        }

        public DiiType getDiiType() {
            return diiType;
        }

        public DiiInputType getInputType() { return inputType; }

        public boolean isValid() {
            return valid;
        }

        public HashedDii toHashedDii(IdentityScope identityScope) {
            return new HashedDii(
                    identityScope,
                    this.diiType,
                    getHashedDiiInput());
        }
    }

}
