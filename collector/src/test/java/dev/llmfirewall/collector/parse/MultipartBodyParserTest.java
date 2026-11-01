package dev.llmfirewall.collector.parse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MultipartBodyParserTest {

    private static final String TYPE = "multipart/form-data; boundary=----WebKitFormBoundaryCI6rtqc3Pd67m1kf";
    private static final String DELIM = "------WebKitFormBoundaryCI6rtqc3Pd67m1kf";

    private final MultipartBodyParser parser = new MultipartBodyParser(10);

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String body() {
        return DELIM + "\r\n"
            + "Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\n"
            + "Content-Type: text/plain\r\n\r\n"
            + "line one\r\nline two\r\n"
            + DELIM + "\r\n"
            + "Content-Disposition: form-data; name=\"purpose\"\r\n\r\n"
            + "attachment\r\n"
            + DELIM + "--\r\n";
    }

    @Test
    void splitsAnUploadIntoItsParts() throws ParseException {
        final MultipartBodyParser.Result result = parser.parse(bytes(body()), TYPE);
        assertTrue(result.complete());
        assertEquals(2, result.parts().size());
        final MultipartBodyParser.Part file = result.parts().get(0);
        assertEquals("file", file.name());
        assertEquals("notes.txt", file.filename());
        assertEquals("text/plain", file.contentType());
        assertArrayEquals(bytes("line one\r\nline two"), file.data(), "line breaks inside the data are kept");
        final MultipartBodyParser.Part field = result.parts().get(1);
        assertEquals("purpose", field.name());
        assertNull(field.filename());
        assertNull(field.contentType());
        assertArrayEquals(bytes("attachment"), field.data());
    }

    @Test
    void ignoresThePreambleAndEpilogueAndAcceptsAQuotedBoundary() throws ParseException {
        final String body = "preamble text\r\n--b1\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--b1--\r\nepilogue";
        final MultipartBodyParser.Result result = parser.parse(bytes(body), "multipart/form-data; BOUNDARY=\"b1\"");
        assertEquals(1, result.parts().size());
        assertArrayEquals(bytes("x"), result.parts().get(0).data());
    }

    @Test
    void keepsBinaryDataByteForByte() throws ParseException {
        final byte[] pdf = {'%', 'P', 'D', 'F', 0, (byte) 0xFF, '\r', '\n', '-', '-'};
        final byte[] head = bytes("--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.pdf\"\r\n"
                                  + "Content-Type: application/pdf\r\n\r\n");
        final byte[] tail = bytes("\r\n--b--");
        final byte[] body = new byte[head.length + pdf.length + tail.length];
        System.arraycopy(head, 0, body, 0, head.length);
        System.arraycopy(pdf, 0, body, head.length, pdf.length);
        System.arraycopy(tail, 0, body, head.length + pdf.length, tail.length);
        assertArrayEquals(pdf, parser.parse(body, "multipart/form-data; boundary=b").parts().get(0).data());
    }

    @Test
    void aTruncatedBodyKeepsWhatArrived() throws ParseException {
        final String whole = body();
        final MultipartBodyParser.Result cut = parser.parse(bytes(whole.substring(0, whole.indexOf("line two") + 4)), TYPE);
        assertFalse(cut.complete());
        assertEquals(1, cut.parts().size());
        assertArrayEquals(bytes("line one\r\nline"), cut.parts().get(0).data());
        final MultipartBodyParser.Result inHeaders = parser.parse(bytes(DELIM + "\r\nContent-Disp"), TYPE);
        assertFalse(inHeaders.complete());
        assertEquals(0, inHeaders.parts().size());
    }

    @Test
    void rejectsBodiesItCannotSplit() {
        assertEquals("multipart:no_boundary", assertThrows(ParseException.class,
            () -> parser.parse(bytes(body()), "multipart/form-data")).code());
        assertEquals("multipart:no_boundary", assertThrows(ParseException.class, () -> parser.parse(bytes(body()), null)).code());
        assertEquals("multipart:no_delimiter", assertThrows(ParseException.class,
            () -> parser.parse(bytes("no parts here"), TYPE)).code());
    }

    @Test
    void capsTheNumberOfParts() throws ParseException {
        final StringBuilder many = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            many.append("--b\r\nContent-Disposition: form-data; name=\"f").append(i).append("\"\r\n\r\nv\r\n");
        }
        many.append("--b--");
        final byte[] body = bytes(many.toString());
        assertEquals("multipart:too_many_parts", assertThrows(ParseException.class,
            () -> new MultipartBodyParser(2).parse(body, "multipart/form-data; boundary=b")).code());
        assertEquals(3, new MultipartBodyParser(3).parse(body, "multipart/form-data; boundary=b").parts().size());
    }

    @Test
    void rejectsANonPositiveLimit() {
        assertThrows(IllegalArgumentException.class, () -> new MultipartBodyParser(0));
    }
}
