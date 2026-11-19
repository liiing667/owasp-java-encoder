package org.owasp.encoder.testing.jakarta_test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.owasp.encoder.Encode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.env.Environment;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.BrowserWebDriverContainer;

/** Actual browser interpretation of server-rendered tag and EL output. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ItemControllerTest {
    private static BrowserWebDriverContainer<?> container;
    private static RemoteWebDriver browser;

    /** Same fixed nested-JSON fixture as ItemController: legal JSON text. */
    private static final String NESTED_JSON
        = "{\"backslash\":\"\\\\\",\"quote\":\"\\\"\","
        + "\"controls\":\"\\b\\t\\n\\f\\r\","
        + "\"lineSeparator\":\"\u2028\",\"paragraphSeparator\":\"\u2029\"}";

    /** Same fixed raw-control fixture as ItemController: illegal in JSON text. */
    private static final String RAW_CONTROLS = "raw\u0000\u0001\u001fcontrols";

    @LocalServerPort
    private int port;

    @BeforeAll
    static void start(@Autowired Environment environment) {
        Testcontainers.exposeHostPorts(environment.getRequiredProperty("local.server.port", Integer.class));
        ChromeOptions options = new ChromeOptions().addArguments("--headless=new");
        container = BrowserFixture.container(options);
        container.start();
        browser = new RemoteWebDriver(container.getSeleniumAddress(), options);
    }

    @AfterAll
    static void stop() {
        try {
            if (browser != null) browser.quit();
        } finally {
            if (container != null) container.stop();
        }
    }

    @Test
    void rendersTagAndFunctionAsTextWithoutCreatingScripts() {
        browser.get("http://host.testcontainers.internal:" + port + "/jakarta-test/item/viewItems");
        assertEquals("View Items", browser.getTitle());
        assertEquals(4, browser.findElements(By.cssSelector("tbody tr")).size());
        assertEquals("top<script>alert(1)</script>", browser.findElement(By.id("b2")).getText());
        assertEquals("fancy <script>alert(1)</script>", browser.findElement(By.id("c2")).getText());
        List<WebElement> scripts = browser.findElements(By.tagName("script"));
        assertEquals(1, scripts.size());
        assertEquals("application/json", scripts.get(0).getDomProperty("type"));
        assertEquals("CSS1Compat", browser.executeScript("return document.compatMode"));
    }

    @Test
    void embeddedJsonKeepsIdentityAndRejectsRawControlCharacters() {
        browser.get("http://host.testcontainers.internal:" + port + "/jakarta-test/item/viewItems");

        // JSON encoding, embedding context and reversibility are one identity:
        // the element holds exactly the document built with Encode.forJson.
        String text = browser.executeScript(
            "return document.getElementById('items-json').textContent;").toString();
        String expected = "["
            + "{\"id\":1,\"name\":\"menu\",\"description\":\"blob\"},"
            + "{\"id\":2,\"name\":\"" + Encode.forJson("top<script>alert(1)</script>")
            + "\",\"description\":\"" + Encode.forJson("fancy <script>alert(1)</script>") + "\"},"
            + "{\"id\":3,\"name\":\"nested-json\",\"description\":\""
            + Encode.forJson(NESTED_JSON) + "\"},"
            + "{\"id\":4,\"name\":\"raw-controls\",\"description\":\""
            + Encode.forJson(RAW_CONTROLS) + "\"}]";
        assertEquals(expected, text);

        // Round trip: parsing the embedded JSON returns the identical strings.
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) browser.executeScript(
            "return JSON.parse(document.getElementById('items-json').textContent);");
        assertEquals(4, items.size());
        assertEquals("menu", items.get(0).get("name"));
        assertEquals("blob", items.get(0).get("description"));
        assertEquals("top<script>alert(1)</script>", items.get(1).get("name"));
        assertEquals("fancy <script>alert(1)</script>", items.get(1).get("description"));
        assertEquals("nested-json", items.get(2).get("name"));
        assertEquals(NESTED_JSON, items.get(2).get("description"));
        assertEquals("raw-controls", items.get(3).get("name"));
        assertEquals(RAW_CONTROLS, items.get(3).get("description"));

        // Legal JSON text is preserved: the nested fixture parses again with
        // its backslash, quote, controls and Unicode line separators intact.
        Object nested = browser.executeScript(
            "return JSON.parse(JSON.parse("
            + "document.getElementById('items-json').textContent)[2].description);");
        assertEquals(Map.of(
            "backslash", "\\",
            "quote", "\"",
            "controls", "\b\t\n\f\r",
            "lineSeparator", "\u2028",
            "paragraphSeparator", "\u2029"), nested);

        // Fail closed: the page never emits a raw control character, and a
        // strict parser rejects one instead of decoding it leniently.
        assertEquals(Boolean.FALSE, browser.executeScript(
            "return /[\\u0000-\\u001f]/.test("
            + "document.getElementById('items-json').textContent);"));
        assertEquals(Boolean.TRUE, browser.executeScript(
            "try { JSON.parse('\"\\u0000\"'); return false; }"
            + " catch (error) { return error instanceof SyntaxError; }"));
    }
}
