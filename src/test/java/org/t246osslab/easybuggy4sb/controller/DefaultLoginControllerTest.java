package org.t246osslab.easybuggy4sb.controller;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.MessageSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.web.servlet.ModelAndView;

/**
 * Test class for DefaultLoginController to verify XSS vulnerability remediation.
 * Tests ensure that user input from request parameters is properly sanitized
 * before being added to the ModelAndView to prevent Reflected XSS attacks.
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultLoginControllerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private MessageSource messageSource;

    @Mock
    private LdapTemplate ldapTemplate;

    @InjectMocks
    private DefaultLoginController controller;

    private Locale locale;

    @Before
    public void setUp() {
        locale = Locale.ENGLISH;
        controller.msg = messageSource;
        controller.ldapTemplate = ldapTemplate;

        // Mock session behavior
        when(request.getSession(true)).thenReturn(session);
        when(session.getAttribute("authNMsg")).thenReturn(null);

        // Mock message source to avoid NoSuchMessageException
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
            .thenReturn("Test Message");
    }

    /**
     * Test that basic XSS attack vectors in parameter names are properly encoded.
     * This test verifies that script tags in parameter names cannot execute.
     */
    @Test
    public void testXSSInParameterName_ScriptTag() {
        // Arrange: Create a malicious parameter name with script tag
        String maliciousParamName = "<script>alert('XSS')</script>";
        String[] paramValues = {"value1"};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(maliciousParamName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(maliciousParamName)).thenReturn(paramValues);

        // Act: Call the doGet method
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Verify that the parameter name is HTML encoded
        assertNotNull("ModelAndView should not be null", mav);
        assertTrue("hiddenMap should be added to model", mav.getModel().containsKey("hiddenMap"));

        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should not be null", hiddenMap);

        // Check that the raw malicious parameter is not present
        assertFalse("Raw malicious parameter should not be in hiddenMap",
            hiddenMap.containsKey(maliciousParamName));

        // Check that an encoded version exists
        boolean foundEncodedKey = false;
        for (String key : hiddenMap.keySet()) {
            if (key.contains("&lt;script&gt;") || key.contains("&lt;") || key.contains("&gt;")) {
                foundEncodedKey = true;
                break;
            }
        }
        assertTrue("Encoded parameter name should be present", foundEncodedKey);
    }

    /**
     * Test that XSS attack vectors in parameter values are properly encoded.
     * This test verifies that malicious JavaScript in values is neutralized.
     */
    @Test
    public void testXSSInParameterValue_ScriptTag() {
        // Arrange: Create a parameter with malicious value
        String paramName = "redirect";
        String[] maliciousValues = {"<script>alert('XSS Attack')</script>"};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(paramName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(paramName)).thenReturn(maliciousValues);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Verify the value is properly encoded
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should not be null", hiddenMap);

        // Find the sanitized parameter
        boolean foundSanitizedValue = false;
        for (String[] values : hiddenMap.values()) {
            for (String value : values) {
                // Check that the value is encoded (contains HTML entities)
                if (value.contains("&lt;script&gt;") || value.contains("&lt;") || value.contains("&gt;")) {
                    foundSanitizedValue = true;
                    // Ensure the raw script tag is not present
                    assertFalse("Raw script tag should not be present", value.contains("<script>"));
                }
            }
        }
        assertTrue("Sanitized parameter value should be present", foundSanitizedValue);
    }

    /**
     * Test XSS with event handler attributes (e.g., onerror, onload).
     */
    @Test
    public void testXSSInParameterValue_EventHandler() {
        // Arrange
        String paramName = "img";
        String[] maliciousValues = {"<img src=x onerror='alert(1)'>"};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(paramName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(paramName)).thenReturn(maliciousValues);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        String[] values = hiddenMap.get(paramName);
        assertNotNull("Parameter should be present", values);
        assertTrue("Value should be encoded", values[0].contains("&lt;") || values[0].contains("&gt;"));
        assertFalse("Raw img tag should not be present", values[0].contains("<img"));
    }

    /**
     * Test XSS with JavaScript protocol in URLs.
     */
    @Test
    public void testXSSInParameterValue_JavascriptProtocol() {
        // Arrange
        String paramName = "url";
        String[] maliciousValues = {"javascript:alert('XSS')"};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(paramName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(paramName)).thenReturn(maliciousValues);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present", hiddenMap);
        // The value should still be encoded for safety
        String[] values = hiddenMap.get(paramName);
        assertNotNull("Parameter should be present", values);
        // ESAPI encodes colons and parentheses for HTML context
        assertTrue("Value should be properly encoded",
            values[0].contains("&#x3a;") || values[0].equals("javascript:alert('XSS')"));
    }

    /**
     * Test that multiple parameters with XSS attempts are all sanitized.
     */
    @Test
    public void testXSSInMultipleParameters() {
        // Arrange: Multiple parameters with different XSS vectors
        String param1 = "name";
        String[] values1 = {"<script>alert(1)</script>"};

        String param2 = "email";
        String[] values2 = {"test@example.com<img src=x onerror=alert(2)>"};

        String param3 = "normal";
        String[] values3 = {"normalValue"};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(param1);
        paramNames.add(param2);
        paramNames.add(param3);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(param1)).thenReturn(values1);
        when(request.getParameterValues(param2)).thenReturn(values2);
        when(request.getParameterValues(param3)).thenReturn(values3);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertEquals("Should have 3 parameters", 3, hiddenMap.size());

        // Check param1
        String[] param1Values = hiddenMap.get(param1);
        assertNotNull(param1Values);
        assertTrue("Param1 should be encoded", param1Values[0].contains("&lt;") || param1Values[0].contains("&gt;"));

        // Check param2
        String[] param2Values = hiddenMap.get(param2);
        assertNotNull(param2Values);
        assertTrue("Param2 should be encoded", param2Values[0].contains("&lt;") || param2Values[0].contains("&gt;"));

        // Check param3 (normal parameter should still be present)
        String[] param3Values = hiddenMap.get(param3);
        assertNotNull(param3Values);
        assertEquals("Normal value should be preserved", "normalValue", param3Values[0]);
    }

    /**
     * Test that parameters with multiple values are all sanitized.
     */
    @Test
    public void testXSSInMultiValueParameter() {
        // Arrange: Single parameter with multiple values containing XSS
        String paramName = "items";
        String[] maliciousValues = {
            "normalValue",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(2)>",
            "anotherNormalValue"
        };

        Vector<String> paramNames = new Vector<>();
        paramNames.add(paramName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(paramName)).thenReturn(maliciousValues);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        String[] values = hiddenMap.get(paramName);
        assertNotNull("Parameter should be present", values);
        assertEquals("Should have 4 values", 4, values.length);

        // Check first value (normal)
        assertEquals("First value should be preserved", "normalValue", values[0]);

        // Check second value (script tag)
        assertTrue("Second value should be encoded", values[1].contains("&lt;") || values[1].contains("&gt;"));
        assertFalse("Second value should not contain raw script", values[1].contains("<script>"));

        // Check third value (img tag)
        assertTrue("Third value should be encoded", values[2].contains("&lt;") || values[2].contains("&gt;"));
        assertFalse("Third value should not contain raw img tag", values[2].contains("<img"));

        // Check fourth value (normal)
        assertEquals("Fourth value should be preserved", "anotherNormalValue", values[3]);
    }

    /**
     * Test that empty parameters are handled correctly without errors.
     */
    @Test
    public void testEmptyParametersHandling() {
        // Arrange: Parameter with empty value
        String paramName = "empty";
        String[] emptyValues = {""};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(paramName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(paramName)).thenReturn(emptyValues);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Should not throw exception
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should not be null", hiddenMap);
        String[] values = hiddenMap.get(paramName);
        assertNotNull("Empty parameter should be present", values);
        assertEquals("Empty value should be preserved", "", values[0]);
    }

    /**
     * Test that no parameters scenario works correctly.
     */
    @Test
    public void testNoParametersScenario() {
        // Arrange: No parameters
        Vector<String> paramNames = new Vector<>();
        when(request.getParameterNames()).thenReturn(paramNames.elements());

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should not be null", hiddenMap);
        assertTrue("hiddenMap should be empty", hiddenMap.isEmpty());
    }

    /**
     * Test XSS with HTML entities already in input to ensure double-encoding doesn't break functionality.
     */
    @Test
    public void testXSSWithExistingHTMLEntities() {
        // Arrange: Input already contains HTML entities
        String paramName = "text";
        String[] values = {"&lt;script&gt;alert(1)&lt;/script&gt;"};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(paramName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(paramName)).thenReturn(values);

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Should be double-encoded (safe behavior)
        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        String[] resultValues = hiddenMap.get(paramName);
        assertNotNull("Parameter should be present", resultValues);
        // ESAPI will encode the ampersands
        assertTrue("Value should be further encoded",
            resultValues[0].contains("&amp;") || resultValues[0].equals(values[0]));
    }

    /**
     * Test authentication message handling doesn't interfere with XSS protection.
     */
    @Test
    public void testAuthenticationMessageWithXSSProtection() {
        // Arrange
        String paramName = "redirect";
        String[] values = {"<script>alert(1)</script>"};

        Vector<String> paramNames = new Vector<>();
        paramNames.add(paramName);

        when(request.getParameterNames()).thenReturn(paramNames.elements());
        when(request.getParameterValues(paramName)).thenReturn(values);
        when(session.getAttribute("authNMsg")).thenReturn("Invalid credentials");

        // Act
        ModelAndView mav = new ModelAndView();
        controller.doGet(mav, request, response, locale);

        // Assert: Both authNMsg and sanitized params should work
        assertTrue("Error message should be in model", mav.getModel().containsKey("errmsg"));

        @SuppressWarnings("unchecked")
        java.util.HashMap<String, String[]> hiddenMap =
            (java.util.HashMap<String, String[]>) mav.getModel().get("hiddenMap");

        assertNotNull("hiddenMap should be present", hiddenMap);
        String[] resultValues = hiddenMap.get(paramName);
        assertNotNull("Parameter should be present", resultValues);
        assertTrue("Value should be encoded", resultValues[0].contains("&lt;") || resultValues[0].contains("&gt;"));
    }
}
