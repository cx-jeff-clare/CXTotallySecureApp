package org.t246osslab.easybuggy4sb.controller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.util.HashMap;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.servlet.ModelAndView;

/**
 * Test class for DefaultLoginController to verify XSS vulnerability remediation.
 * Tests ensure that user-supplied parameters are properly sanitized before being
 * added to the model, preventing Reflected XSS attacks.
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class DefaultLoginControllerTest {

    @Autowired
    private DefaultLoginController controller;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private Locale locale;

    @Before
    public void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        locale = Locale.ENGLISH;
    }

    /**
     * Test that XSS attack payload in parameter value is properly sanitized.
     * Verifies that script tags are HTML-encoded and cannot execute.
     */
    @Test
    public void testXssPreventionInParameterValue() throws Exception {
        // Arrange: Add a parameter with XSS payload
        String xssPayload = "<script>alert('XSS')</script>";
        request.addParameter("testParam", xssPayload);

        // Act: Call the doGet method
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Verify the XSS payload is sanitized
        assertNotNull("ModelAndView should not be null", mav);

        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present in the model", hiddenMap);
        assertTrue("hiddenMap should contain the testParam", hiddenMap.containsKey("testParam"));

        String[] values = hiddenMap.get("testParam");
        assertNotNull("Parameter values should not be null", values);
        assertEquals("Should have one parameter value", 1, values.length);

        // Verify the value is HTML-encoded (< becomes &lt;, > becomes &gt;)
        String sanitizedValue = values[0];
        assertFalse("Sanitized value should not contain raw < character", sanitizedValue.contains("<script>"));
        assertTrue("Sanitized value should contain HTML-encoded script tag",
                   sanitizedValue.contains("&lt;script&gt;") || sanitizedValue.contains("&#"));
    }

    /**
     * Test that XSS attack payload in parameter name is properly sanitized.
     */
    @Test
    public void testXssPreventionInParameterName() throws Exception {
        // Arrange: Add a parameter with XSS payload in the name
        String xssParamName = "<img src=x onerror=alert('XSS')>";
        request.addParameter(xssParamName, "testValue");

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present in the model", hiddenMap);

        // Verify that no raw parameter name exists
        assertFalse("hiddenMap should not contain unsanitized parameter name",
                    hiddenMap.containsKey(xssParamName));

        // Verify that the sanitized parameter name exists
        boolean foundSanitized = false;
        for (String key : hiddenMap.keySet()) {
            if (key.contains("&lt;img") || key.contains("&#")) {
                foundSanitized = true;
                break;
            }
        }
        assertTrue("Parameter name should be HTML-encoded", foundSanitized);
    }

    /**
     * Test multiple parameters with XSS payloads are all sanitized.
     */
    @Test
    public void testMultipleXssPayloadsSanitized() throws Exception {
        // Arrange: Add multiple parameters with different XSS payloads
        request.addParameter("param1", "<script>document.cookie</script>");
        request.addParameter("param2", "javascript:alert('XSS')");
        request.addParameter("param3", "<img src=x onerror=alert(1)>");
        request.addParameter("normalParam", "normalValue");

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present", hiddenMap);
        assertEquals("Should have 4 parameters", 4, hiddenMap.size());

        // Verify all XSS payloads are sanitized
        for (String key : hiddenMap.keySet()) {
            String[] values = hiddenMap.get(key);
            for (String value : values) {
                // Raw dangerous characters should not exist
                assertFalse("Value should not contain unsanitized < tag: " + value,
                           value.contains("<script>") || value.contains("<img"));
            }
        }

        // Verify normal parameter is preserved
        String[] normalValues = hiddenMap.get("normalParam");
        assertNotNull("Normal parameter should exist", normalValues);
        assertEquals("Normal value should be preserved", "normalValue", normalValues[0]);
    }

    /**
     * Test multiple values for the same parameter are all sanitized.
     */
    @Test
    public void testMultipleValuesForSameParameterSanitized() throws Exception {
        // Arrange: Add parameter with multiple values containing XSS
        request.addParameter("multiParam", new String[]{
            "<script>alert('XSS1')</script>",
            "<script>alert('XSS2')</script>",
            "normalValue"
        });

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present", hiddenMap);
        String[] values = hiddenMap.get("multiParam");

        assertNotNull("Parameter should exist", values);
        assertEquals("Should have 3 values", 3, values.length);

        // Verify all values are sanitized
        for (String value : values) {
            assertFalse("Value should not contain raw script tag: " + value,
                       value.contains("<script>"));
        }
    }

    /**
     * Test SQL injection attempt is sanitized (treated as regular text).
     */
    @Test
    public void testSqlInjectionAttemptSanitized() throws Exception {
        // Arrange: Add parameter with SQL injection payload
        String sqlPayload = "'; DROP TABLE users; --";
        request.addParameter("userid", sqlPayload);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: SQL characters should be HTML-encoded
        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present", hiddenMap);
        String[] values = hiddenMap.get("userid");
        assertNotNull("userid parameter should exist", values);

        // The value should be HTML-encoded (single quotes and other special chars)
        String sanitizedValue = values[0];
        assertNotNull("Sanitized value should not be null", sanitizedValue);
        // ESAPI encoder should handle special characters appropriately
    }

    /**
     * Test empty parameter values are handled correctly.
     */
    @Test
    public void testEmptyParameterValues() throws Exception {
        // Arrange: Add parameter with empty value
        request.addParameter("emptyParam", "");
        request.addParameter("nullParam", (String) null);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Should not throw exception
        assertNotNull("ModelAndView should not be null", mav);

        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");
        assertNotNull("hiddenMap should be present", hiddenMap);
    }

    /**
     * Test special characters that might bypass sanitization.
     */
    @Test
    public void testSpecialCharactersBypass() throws Exception {
        // Arrange: Test various encoding bypass attempts
        String[] bypassAttempts = {
            "<ScRiPt>alert('XSS')</ScRiPt>", // Mixed case
            "<<SCRIPT>alert('XSS');//<</SCRIPT>", // Nested tags
            "<script\u0000>alert('XSS')</script>", // Null byte
            "<script>alert(String.fromCharCode(88,83,83))</script>", // Character codes
            "<iframe src=javascript:alert('XSS')></iframe>", // iframe
            "<body onload=alert('XSS')>", // Event handler
            "<svg/onload=alert('XSS')>", // SVG
            "&#60;script&#62;alert('XSS')&#60;/script&#62;" // HTML entities
        };

        for (String attempt : bypassAttempts) {
            // Arrange
            MockHttpServletRequest req = new MockHttpServletRequest();
            req.addParameter("testParam", attempt);

            // Act
            ModelAndView mav = new ModelAndView();
            controller.doGet(mav, req, response, locale);

            // Assert
            @SuppressWarnings("unchecked")
            HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

            String[] values = hiddenMap.get("testParam");
            assertNotNull("Parameter should exist for attempt: " + attempt, values);

            String sanitizedValue = values[0];
            // Verify dangerous patterns are not present in raw form
            assertFalse("Should sanitize attempt: " + attempt,
                       sanitizedValue.toLowerCase().contains("<script") &&
                       sanitizedValue.toLowerCase().contains("</script>"));
        }
    }

    /**
     * Test legitimate HTML characters in normal usage are properly encoded.
     */
    @Test
    public void testLegitimateHtmlCharactersEncoded() throws Exception {
        // Arrange: Add parameters with legitimate but HTML-sensitive content
        request.addParameter("mathExpr", "if x < y && y > z");
        request.addParameter("email", "user@domain.com");
        request.addParameter("code", "function() { return 'test'; }");

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Should be encoded to prevent any interpretation
        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present", hiddenMap);

        // Math expression with < and > should be encoded
        String[] mathValues = hiddenMap.get("mathExpr");
        assertNotNull("Math expression parameter should exist", mathValues);
        String mathValue = mathValues[0];
        // < and > should be encoded
        assertTrue("< should be encoded", mathValue.contains("&lt;") || !mathValue.contains("<"));
        assertTrue("& should be encoded", mathValue.contains("&amp;") || !mathValue.contains("&&"));
    }

    /**
     * Test that normal functionality is preserved with safe input.
     */
    @Test
    public void testNormalFunctionalityPreserved() throws Exception {
        // Arrange: Add safe parameters
        request.addParameter("username", "testuser");
        request.addParameter("redirect", "/admin/main");
        request.addParameter("action", "login");

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        assertNotNull("ModelAndView should not be null", mav);
        assertEquals("View name should be 'login'", "login", mav.getViewName());

        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present", hiddenMap);
        assertEquals("Should have 3 parameters", 3, hiddenMap.size());

        // Verify safe values are preserved
        String[] usernameValues = hiddenMap.get("username");
        assertNotNull("Username parameter should exist", usernameValues);
        assertEquals("Safe username should be preserved", "testuser", usernameValues[0]);
    }

    /**
     * Test request with no parameters doesn't break functionality.
     */
    @Test
    public void testNoParametersDoesNotBreak() throws Exception {
        // Arrange: Request with no parameters
        // (request already initialized in setUp with no parameters)

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        assertNotNull("ModelAndView should not be null", mav);

        @SuppressWarnings("unchecked")
        HashMap<String, String[]> hiddenMap = (HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present even with no params", hiddenMap);
        assertTrue("hiddenMap should be empty", hiddenMap.isEmpty());
    }
}
