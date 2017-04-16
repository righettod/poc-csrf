package eu.righettod.poccsrf.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Filter in charge of validating each incoming HTTP request about Headers and CSRF token.
 * It is called for all requests to backend destination.
 *
 * We use the approach in which:
 * - The CSRF token is changed after each valid HTTP exchange
 * - The custom Header name for the CSRF token transmission is fixed
 * - A CSRF token is associated to a backend service URI in order to enable the support for multiple parallel Ajax request from the same application
 * - The CSRF cookie name is the backend service name prefixed with a fixed prefix
 *
 * Here for the POC we show the "access denied" reason in the response but in production code only return a generic message !!!
 *
 * @see "https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet"
 * @see "https://wiki.mozilla.org/Security/Origin"
 * @see "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
 * @see "https://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue/"
 */
@WebFilter("/backend/*")
public class CSRFValidationFilter implements Filter {

    /**
     * JVM param name used to define the target origin
     */
    public static final String TARGET_ORIGIN_JVM_PARAM_NAME = "target.origin";

    /**
     * Name of the custom HTTP header used to transmit the CSRF token and also to prefix the CSRF cookie for the expected backend service
     */
    private static final String CSRF_TOKEN_NAME = "X-TOKEN";

    /**
     * Logger
     */
    private static final Logger LOG = LoggerFactory.getLogger(CSRFValidationFilter.class);

    /**
     * Application expected deployment domain: named "Target Origin" in OWASP CSRF article
     */
    private URL targetOrigin;

    /***
     * Secure generator
     */
    private final SecureRandom secureRandom = new SecureRandom();


    /**
     * {@inheritDoc}
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) request;
        HttpServletResponse httpResp = (HttpServletResponse) response;
        String accessDeniedReason;

        /* STEP 1: Verifying Same Origin with Standard Headers */
        //Try to get the source from the "Origin" header
        String source = httpReq.getHeader("Origin");
        if (this.isBlank(source)) {
            //If empty then fallback on "Referer" header
            source = httpReq.getHeader("Referer");
            //If this one is empty too then we trace the event and we block the request (recommendation of the article)...
            if (this.isBlank(source)) {
                accessDeniedReason = "CSRFValidationFilter: ORIGIN and REFERER request headers are both absent/empty so we block the request !";
                LOG.warn(accessDeniedReason);
                httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
                return;
            }
        }

        //Compare the source against the expected target origin
        URL sourceURL = new URL(source);
        if (!this.targetOrigin.getProtocol().equals(sourceURL.getProtocol()) || !this.targetOrigin.getHost().equals(sourceURL.getHost()) || this.targetOrigin.getPort() != sourceURL.getPort()) {
            //One the part do not match so we trace the event and we block the request
            accessDeniedReason = String.format("CSRFValidationFilter: Protocol/Host/Port do not fully matches so we block the request! (%s != %s) ", this.targetOrigin, sourceURL);
            LOG.warn(accessDeniedReason);
            httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
            return;
        }

        /* STEP 2: Verifying CSRF token using "Double Submit Cookie" approach */
        //If CSRF token cookie is absent from the request then we provide one in response but we stop the process at this stage.
        //Using this way we implement the first providing of token
        Cookie tokenCookie = null;
        if (httpReq.getCookies() != null) {
            String csrfCookieExpectedName = this.determineCookieName(httpReq);
            tokenCookie = Arrays.stream(httpReq.getCookies()).filter(c -> c.getName().equals(csrfCookieExpectedName)).findFirst().orElse(null);
        }
        if (tokenCookie == null || this.isBlank(tokenCookie.getValue())) {
            LOG.info("CSRFValidationFilter: CSRF cookie absent or value is null/empty so we provide one and return an HTTP NO_CONTENT response !");
            //Add the CSRF token cookie and header
            this.addTokenCookieAndHeader(httpReq, httpResp);
            //Set response state to "204 No Content" in order to allow the requester to clearly identify an initial response providing the initial CSRF token
            httpResp.setStatus(HttpServletResponse.SC_NO_CONTENT);
        } else {
            //If the cookie is present then we pass to validation phase
            //Get token from the custom HTTP header (part under control of the requester)
            String tokenFromHeader = httpReq.getHeader(CSRF_TOKEN_NAME);
            //If empty then we trace the event and we block the request
            if (this.isBlank(tokenFromHeader)) {
                accessDeniedReason = "CSRFValidationFilter: Token provided via HTTP Header is absent/empty so we block the request !";
                LOG.warn(accessDeniedReason);
                httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
            } else if (!tokenFromHeader.equals(tokenCookie.getValue())) {
                //Verify that token from header and one from cookie are the same
                //Here is not the case so we trace the event and we block the request
                accessDeniedReason = "CSRFValidationFilter: Token provided via HTTP Header and via Cookie are not equals so we block the request !";
                LOG.warn(accessDeniedReason);
                httpResp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedReason);
            } else {
                //Verify that token from header and one from cookie matches
                //Here is the case so we let the request reach the target component (ServiceServlet, jsp...) and add a new token when we get back the bucket
                HttpServletResponseWrapper httpRespWrapper = new HttpServletResponseWrapper(httpResp);
                chain.doFilter(request, httpRespWrapper);
                //Add the CSRF token cookie and header
                this.addTokenCookieAndHeader(httpReq, httpRespWrapper);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        //To easier the configuration, we load the target expected origin from an JVM property
        //Reconfiguration only require an application restart that is generally acceptable
        try {
            this.targetOrigin = new URL(System.getProperty(TARGET_ORIGIN_JVM_PARAM_NAME));
        } catch (MalformedURLException e) {
            LOG.error("Cannot init the filter !", e);
            throw new ServletException(e);
        }
        LOG.info("CSRFValidationFilter: Filter init, set expected target origin to '{}'.", this.targetOrigin);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy() {
        LOG.info("CSRFValidationFilter: Filter shutdown");
    }

    /**
     * Check if a string is null or empty (including containing only spaces)
     *
     * @param s Source string
     * @return TRUE if source string is null or empty (including containing only spaces)
     */
    private boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * Generate a new CSRF token
     *
     * @return The token a string
     */
    private String generateToken() {
        byte[] buffer = new byte[50];
        this.secureRandom.nextBytes(buffer);
        return DatatypeConverter.printHexBinary(buffer);
    }

    /**
     * Determine the name of the CSRF cookie for the targeted backend service
     *
     * @param httpRequest Source HTTP request
     * @return The name of the cookie as a string
     */
    private String determineCookieName(HttpServletRequest httpRequest) {
        String backendServiceName = httpRequest.getRequestURI().replaceAll("/", "-");
        return CSRF_TOKEN_NAME + "-" + backendServiceName;
    }

    /**
     * Add the CSRF token cookie and header to the provided HTTP response object
     *
     * @param httpRequest  Source HTTP request
     * @param httpResponse HTTP response object to update
     */
    private void addTokenCookieAndHeader(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        //Get new token
        String token = this.generateToken();
        //Add cookie manually because the current Cookie class implementation do not support the "SameSite" attribute
        //We let the adding of the "Secure" cookie attribute to the reverse proxy rewriting...
        //Here we lock the cookie from JS access and we use the SameSite new attribute protection
        String cookieSpec = String.format("%s=%s; Path=%s; HttpOnly; SameSite=Strict", this.determineCookieName(httpRequest), token, httpRequest.getRequestURI());
        httpResponse.addHeader("Set-Cookie", cookieSpec);
        //Add cookie header to give access to the token to the JS code
        httpResponse.setHeader(CSRF_TOKEN_NAME, token);
    }
}
