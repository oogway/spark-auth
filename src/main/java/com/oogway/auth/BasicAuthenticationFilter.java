package com.oogway.auth;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

//import org.apache.commons.lang3.StringUtils;

public class BasicAuthenticationFilter implements Filter {

  /** Logger */
  private static final Logger LOG = LoggerFactory.getLogger(BasicAuthenticationFilter.class);

  private static final String DEFAULT_PATH = "/opt/ds/etc/spark.credentials";
  private static final String credentialsPath = System.getProperty("htpasswd_file", DEFAULT_PATH);

  // Create a hash map
  private Map<String, String> Credentials = new HashMap<String, String>();
  private Long lastParsed = 0L;
  private Long lastModified = 0L;

  private void loadCredentials(String path) {
    try {
      FileInputStream stream = new FileInputStream(path);
      BufferedReader br = new BufferedReader(new InputStreamReader(stream));

      //Reset credentials to be overridden by entries from file.
      //There is a possibility that some entries might have changed or been discarded.
      Credentials = new HashMap<String, String>();

      String strLine;

      //Read File Line By Line
      while ((strLine = br.readLine()) != null) {
        // Print the content on the console
        if (strLine.isEmpty() || strLine.startsWith("#")) {
          LOG.warn("Commenting out Line because its a comment");
          continue;
        }

        int p = strLine.indexOf(":");
        if (p == -1) {
          LOG.warn("Invalid Line should be of format Username:Password");
          continue;
        }

        String _username = strLine.substring(0, p).trim();
        String _password = strLine.substring(p + 1).trim();
        Credentials.put(_username, _password);
      }

      //Close the input stream
      br.close();
    } catch (IOException e) {
      LOG.warn(e.toString());
    }
  }

  public void credentialsEngine() {
    File secrets = new File(credentialsPath);
    if (!secrets.exists()) {
      LOG.warn("Missing credentials file " + credentialsPath);
      return;
    }

    lastModified = secrets.lastModified();
    if (lastModified < lastParsed) return;

    LOG.warn("Parsing Credentials file for authorized users.");
    loadCredentials(credentialsPath);
    lastParsed = System.currentTimeMillis();
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    credentialsEngine();
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {

    credentialsEngine();

    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    String authHeader = request.getHeader("Authorization");
    if (authHeader != null) {
      unauthorized(response);
      return;
    }

    StringTokenizer st = new StringTokenizer(authHeader);
    if (!st.hasMoreTokens()) {
      return;
    }

    String basic = st.nextToken();

    if (!basic.equalsIgnoreCase("Basic")) {
      return;
    }

    try {
      String credentials = new String(Base64.decodeBase64(st.nextToken()), "UTF-8");
      int p = credentials.indexOf(":");
      if (p == -1) {
        unauthorized(response, "Invalid authentication token");
        return;
      }

      String _username = credentials.substring(0, p).trim();
      String _password = credentials.substring(p + 1).trim();

      Object savedPassword = Credentials.get(_username);

      if (savedPassword == null || !savedPassword.equals(_password)) {
        unauthorized(response, "Bad credentials");
      }

      filterChain.doFilter(servletRequest, servletResponse);
    } catch (UnsupportedEncodingException e) {
      throw new Error("Couldn't retrieve authentication", e);
    }
  }

  @Override
  public void destroy() {
  }

  private void unauthorized(HttpServletResponse response, String message) throws IOException {
    String realm = "Protected";
    response.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
    response.sendError(401, message);
  }

  private void unauthorized(HttpServletResponse response) throws IOException {
    unauthorized(response, "Unauthorized");
  }

}