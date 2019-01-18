import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * CSSLCertificateFetcher
 */
public class SSLCertificateFetcher {

  private static final String ANSI_RESET = "\u001B[0m";
  private static final String ANSI_BLACK = "\u001B[30m";
  private static final String ANSI_RED = "\u001B[31m";
  private static final String ANSI_GREEN = "\u001B[32m";
  private static final String ANSI_YELLOW = "\u001B[33m";
  private static final String ANSI_BLUE = "\u001B[34m";
  private static final String ANSI_PURPLE = "\u001B[35m";
  private static final String ANSI_CYAN = "\u001B[36m";
  private static final String ANSI_WHITE = "\u001B[37m";

  private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
  private static final String PROXY_HOST = "proxyHost";
  private static final String PROXY_PORT = "proxyPort";
  private static final String PASSPHRASE = "passphrase";
  private static final String PROXY_USER = "proxyUser";
  private static final String PROXY_PASSWORD = "proxyPassword";
  private static final String URL = "url";
  private static final String TRUSTSTORE = "truststore";

  public static void main(final String[] args) throws Exception {
    SSLCertificateFetcher fetcher = new SSLCertificateFetcher();
    try {
      boolean valid = fetcher.initialize(args);

      if (valid) {
        fetcher.fetch();
      } else {
        readme();
      }
    } catch (Exception e) {
      readme();
    }
  }

  private static void readme() {
    System.out.println("Usage: " + SSLCertificateFetcher.class.getName() + " " + URL + "=[url*] " + TRUSTSTORE + "=[truststore*] " + PASSPHRASE + "=[passphrase] " + PROXY_HOST
        + "=[proxyHost] " + PROXY_PORT + "=[proxyPort] " + PROXY_USER + "=[proxyUser] " + PROXY_PASSWORD + "=[proxyPassword]\n"
        + "passphrase, proxy details are not mandatory. Can be used default " + "in case when they are " + "not specified");
  }

  private String proxyHost = null;
  private Integer proxyPort = null;
  private String remoteUrl;
  private char[] passphrase;
  private Proxy proxy = null;
  private String truststore;

  private boolean initialize(String... args) {
    Map<String, String> paramsMap = new HashMap<>();
    // parsing all passed parameters and storing them in the map
    for (String arg : args) {
      paramsMap.put(arg.split("=")[0].replaceAll(" ", ""), arg.split("=")[1].replaceAll(" ", ""));
    }
    // Writing out all parameters that were passed to java
    paramsMap.forEach((k, v) -> System.out.println(k + " = " + (k.toLowerCase().contains("pass") ? "*******" : v)));

    // check if proxy parameters were passed in. If yes, then enable Proxy
    if (paramsMap.containsKey(PROXY_HOST)) {
      proxyHost = paramsMap.get(PROXY_HOST);
    }
    if (paramsMap.containsKey(PROXY_PORT)) {
      proxyPort = Integer.parseInt(paramsMap.get(PROXY_PORT));
    }
    if (proxyHost != null && proxyPort != null) {
      SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
      proxy = new Proxy(Proxy.Type.HTTP, addr);
    } else {
      System.out.println("Connecting to address without enabled proxy settings. ");
    }

    // now checking if host,port and passphrase parameters were passed succesfully
    if (paramsMap.containsKey(URL)) {
      remoteUrl = paramsMap.get(URL);
    } else {
      return false;
    }

    final String p = paramsMap.getOrDefault(PASSPHRASE, "changeit");
    passphrase = p.toCharArray();

    if (paramsMap.containsKey(PROXY_USER) && paramsMap.containsKey(PROXY_PASSWORD)) {
      Authenticator.setDefault(new Authenticator() {

        @Override
        public PasswordAuthentication getPasswordAuthentication() {
          return new PasswordAuthentication(paramsMap.get(PROXY_USER), paramsMap.get(PROXY_PASSWORD).toCharArray());
        }
      });
    }

    truststore = paramsMap.get(TRUSTSTORE);
    if (truststore == null) {
      System.out.println("'" + TRUSTSTORE + "' must be defined.");
      return false;
    }
    return true;
  }

  private void fetch() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidNameException {

    File file = new File(truststore);

    final KeyStore ks = getKeyStore(passphrase, file);
    final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ks);

    // Create a new trust manager that trust all certificates
    final X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
    final SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
    TrustManager[] trustAllCerts = new TrustManager[]{tm};

    // Activate the new trust manager
    try {
      SSLContext sc = SSLContext.getInstance("TLS");
      sc.init(null, trustAllCerts, new java.security.SecureRandom());
      HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    } catch (Exception e) {
      e.printStackTrace();
      return;
    }

    URL url = new URL(remoteUrl);
    final HttpURLConnection conn;
    if (proxy != null) {
      conn = (HttpURLConnection) url.openConnection(proxy);
    } else {
      conn = (HttpURLConnection) url.openConnection();
    }
    conn.setReadTimeout(10_000);
    System.out.println("Starting SSL handshake...");

    String defaultSelection;

    try {
      conn.connect();
      System.out.println();
      printSuccess("Connection could successfully be established, certificate is already trusted");
      defaultSelection = "q";
    } catch (SSLException e) {
      e.printStackTrace(System.out);
      System.out.println();
      printError("Error, certificate is NOT trusted");
      defaultSelection = "1";
    }

    final X509Certificate[] chain = tm.chain;
    if (chain == null) {
      printError("Could not obtain server certificate chain");
      return;
    }

    final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

    System.out.println();
    System.out.println("Server sent " + chain.length + " certificate(s):");
    System.out.println();
    final MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    final MessageDigest md5 = MessageDigest.getInstance("MD5");
    for (int i = 0; i < chain.length; i++) {
      final X509Certificate cert = chain[i];
      System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
      System.out.println("   Issuer  " + cert.getIssuerDN());
      sha1.update(cert.getEncoded());
      System.out.println("   sha1    " + toHexString(sha1.digest()));
      md5.update(cert.getEncoded());
      System.out.println("   md5     " + toHexString(md5.digest()));
      System.out.println();
    }

    System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [" + defaultSelection + "]");
    final String line = Objects.toString(reader.readLine(), "").trim();
    int k;
    try {
      String option = (line.length() == 0) ? defaultSelection : line;
      k = Integer.parseInt(option) - 1;
    } catch (final NumberFormatException e) {
      System.out.println("KeyStore not changed");
      return;
    }

    final X509Certificate cert = chain[k];

    final String alias = getTruststoreAlias(url, k, cert);

    String backup = null;

    if (ks.containsAlias(alias)) {
      printSuccess("Certificate is already in the keystore.");
    } else {
      if (ks.size() > 0) {
        backup = file.getAbsolutePath() + "." + new SimpleDateFormat("yyyyMMdd").format(new Date());
        try (OutputStream out = new FileOutputStream(backup)) {
          ks.store(out, passphrase);
        }
      }

      ks.setCertificateEntry(alias, cert);
      try (OutputStream out = new FileOutputStream(file)) {
        ks.store(out, passphrase);
      }

      System.out.println();
      System.out.println(cert);
      System.out.println();
      if (backup != null) {
        System.out.println("Created backup of keystore " + backup);
      }
      printSuccess("Added certificate to keystore '" + file.getAbsolutePath() + "' using alias '" + alias + "'");
    }

  }

  private KeyStore getKeyStore(char[] passphrase, File file) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
    final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    if (file.isFile() && file.exists()) {
      System.out.println("Loading KeyStore " + file + "...");
      try (InputStream in = new FileInputStream(file)) {
        ks.load(in, passphrase);
      }
    } else {
      ks.load(null, passphrase);
      System.out.println("Creating empty truststore " + file + "...");
    }
    return ks;
  }

  private String getTruststoreAlias(URL url, int k, X509Certificate cert) throws InvalidNameException {
    String cn = getCN(cert);
    String alias = url.getHost();
    if (cn != null) {
      alias += " (" + cn + ")";
    }
    alias += " (" + SSLCertificateFetcher.class.getSimpleName() + " chain index: " + (k + 1) + ")";
    return alias;
  }

  private String getCN(X509Certificate cert) throws InvalidNameException {
    String dn = cert.getSubjectX500Principal().getName();
    LdapName ldapDN = new LdapName(dn);
    for (Rdn rdn : ldapDN.getRdns()) {
      if ("CN".equals(rdn.getType())) {
        return Objects.toString(rdn.getValue(), null);
      }
    }
    return null;
  }

  private String toHexString(final byte[] bytes) {
    final StringBuilder sb = new StringBuilder(bytes.length * 3);

    for (byte aByte : bytes) {
      int b = aByte & 0xff;
      sb.append(HEXDIGITS[b >> 4]);
      sb.append(HEXDIGITS[b & 15]);
      sb.append(' ');
    }
    return sb.toString();
  }

  private void printError(String message) {
    System.out.println(ANSI_RED + message + ANSI_RESET);
  }

  private void printSuccess(String message) {
    System.out.println(ANSI_GREEN + message + ANSI_RESET);
  }

  private static final class SavingTrustManager implements X509TrustManager {

    private final X509TrustManager tm;
    private X509Certificate[] chain;

    SavingTrustManager(final X509TrustManager tm) {
      this.tm = tm;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
      throw new UnsupportedOperationException();
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
      this.chain = chain;
      this.tm.checkServerTrusted(chain, authType);
    }
  }
}
