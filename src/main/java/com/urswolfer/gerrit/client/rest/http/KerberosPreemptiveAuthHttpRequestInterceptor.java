package com.urswolfer.gerrit.client.rest.http;

import com.urswolfer.gerrit.client.rest.GerritAuthData;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.ContextAwareAuthScheme;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.KerberosScheme;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.protocol.HttpContext;

import java.net.URI;
import java.security.Principal;
import java.util.concurrent.locks.ReentrantLock;

/**
 * With preemptive auth, it will send the basic authentication response even before the server gives an unauthorized
 * response in certain situations, thus reducing the overhead of making the connection again.
 *
 * Based on:
 * https://subversion.jfrog.org/jfrog/build-info/trunk/build-info-client/src/main/java/org/jfrog/build/client/PreemptiveHttpClient.java
 *
 * @author Urs Wolfer
 */
class KerberosPreemptiveAuthHttpRequestInterceptor implements HttpRequestInterceptor {
    static final String PREEMPTIVE_AUTH = "preemptive-auth";

    private GerritAuthData authData;

    KerberosPreemptiveAuthHttpRequestInterceptor(GerritAuthData authData) {
        this.authData = authData;
    }

    @Override
    public void process(final HttpRequest request,final HttpContext context) {
        // never ever send credentials preemptively to a host which is not the configured Gerrit host
        if (!isForGerritHost(request)) {
            return;
        }


        AuthState authState = (AuthState) context.getAttribute(HttpClientContext.TARGET_AUTH_STATE);

        // if no auth scheme available yet, try to initialize it preemptively
        if (authState.getAuthScheme() == null) {
            Credentials use_jaas_creds = new Credentials() {
                public String getPassword() {
                    return null;
                }

                public Principal getUserPrincipal() {
                    return null;
                }
            };
            AuthScheme authScheme = (AuthScheme) context.getAttribute(PREEMPTIVE_AUTH);
            authState.update(authScheme, use_jaas_creds);
        }
    }

    /**
     * Checks if request is intended for Gerrit host.
     */
    private boolean isForGerritHost(HttpRequest request) {
        if (!(request instanceof HttpRequestWrapper)) return false;
        HttpRequest originalRequest = ((HttpRequestWrapper) request).getOriginal();
        if (!(originalRequest instanceof HttpRequestBase)) return false;
        URI uri = ((HttpRequestBase) originalRequest).getURI();
        URI authDataUri = URI.create(authData.getHost());
        if (uri == null || uri.getHost() == null) return false;
        boolean hostEquals = uri.getHost().equals(authDataUri.getHost());
        boolean portEquals = uri.getPort() == authDataUri.getPort();
        return hostEquals && portEquals;
    }
}
