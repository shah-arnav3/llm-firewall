package dev.llmfirewall.collector.parse;

/** A parse failure carrying a content-free code such as {@code json:syntax} or {@code multipart:no_boundary}. */
public final class ParseException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String code;

    public ParseException(String code) {
        super(code);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
