package no.ngu.oauth2.utils;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Properties;

public class Configuration {

  private String iss;
  private String aud;
  private String scope;
  private String tokenEndpoint;
  private X509Certificate certificate;
  private PrivateKey privateKey;
  private String consumerOrg;
  private Boolean jsonOutput = false;
  private Boolean verify = false;
  private String kid;
  private String testFileName;
  private String testReport;
  private String testAttachment1FileName;
  private String testAttachment2FileName;
  private String testAttachment3FileName;
  private String testAttachment4FileName;
  private String apiEndpoint;
  private String vedleggEndpoint;
  private String userId;

  private String verificationEndpoint;

  public String getIss() {
    return iss;
  }

  public void setIss(String iss) {
    this.iss = iss;
  }

  public String getAud() {
    return aud;
  }

  public void setAud(String aud) {
    this.aud = aud;
  }

  public String getConsumerOrg() {
    return consumerOrg;
  }

  public void setConsumerOrg(String consumerOrg) {
    this.consumerOrg = consumerOrg;
  }

  public Boolean getJsonOutput() {
    return jsonOutput;
  }

  public void setJsonOutput(Boolean jsonOutput) {
    this.jsonOutput = jsonOutput;
  }

  public Boolean getVerify() {
    return verify;
  }

  public void setVerify(Boolean verify) {
    this.verify = verify;
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public void setCertificate(X509Certificate certificate) {
    this.certificate = certificate;
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public String getScope() {
    return scope;
  }

  public void setScope(String scope) {
    this.scope = scope;
  }

  public String getTokenEndpoint() {
    return tokenEndpoint;
  }

  public void setTokenEndpoint(String tokenEndpoint) {
    this.tokenEndpoint = tokenEndpoint;
  }

  public boolean hasTokenEndpoint() {
    return tokenEndpoint != null;
  }

  public String getKid() {
    return kid;
  }

  public void setKid(String kid) {
    this.kid = kid;
  }

  public boolean hasKid() {
    return kid != null;
  }

  public String getVerificationEndpoint() {
    return verificationEndpoint;
  }

  public void setVerificationEndpoint(String verificationEndpoint) {
    this.verificationEndpoint = verificationEndpoint;
  }

  public String getTestFileName() {
    return testFileName;
  }

  public void setTestFileName(String testFileName) {
    this.testFileName = testFileName;
  }

  public String getTestReport() {
    return testReport;
  }

  public void setTestReport(String testReport) {
    this.testReport = testReport;
  }

  public String getAttachment1TestFileName() {
    return testAttachment1FileName;
  }

  public void setTestAttachment1FileName(String testAttachmentFileName) {
    this.testAttachment1FileName = testAttachmentFileName;
  }

  public String getAttachment2TestFileName() {
    return testAttachment2FileName;
  }

  public void setTestAttachment2FileName(String testAttachmentFileName) {
    this.testAttachment2FileName = testAttachmentFileName;
  }

  public String getAttachment3TestFileName() {
    return testAttachment3FileName;
  }

  public void setTestAttachment3FileName(String testAttachmentFileName) {
    this.testAttachment3FileName = testAttachmentFileName;
  }

  public String getAttachment4TestFileName() {
    return testAttachment4FileName;
  }

  public void setTestAttachment4FileName(String testAttachmentFileName) {
    this.testAttachment4FileName = testAttachmentFileName;
  }

  public String getApiEndpoint() {
    return apiEndpoint;
  }

  public void setApiEndpoint(String apiEndpoint) {
    this.apiEndpoint = apiEndpoint;
  }

  public String getVedleggEndpoint() {
    return vedleggEndpoint;
  }

  public void setVedleggEndpoint(String vedleggEndpoint) {
    this.vedleggEndpoint = vedleggEndpoint;
  }

  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public static Configuration load(String[] args) throws Exception {
    Configuration config = new Configuration();

    if (args.length == 0 || (Arrays.asList(args).contains("--json") || Arrays.asList(args).contains("--verify"))) {

      Properties props = readPropertyFile("example-client.properties");

      config.setIss(props.getProperty("issuer"));
      config.setAud(props.getProperty("audience"));
      config.setConsumerOrg(props.getProperty("consumer_org"));
      config.setScope(props.getProperty("scope"));
      config.setTokenEndpoint(props.getProperty("token_endpoint"));
      config.setKid(props.getProperty("kid"));

      config.setVerificationEndpoint(props.getProperty("verification_endpoint"));
      config.setApiEndpoint(props.getProperty("api_endpoint"));
      config.setVedleggEndpoint(props.getProperty("vedlegg_endpoint"));
      config.setUserId(props.getProperty("user_uuid"));

      config.setTestFileName("GeotekniskUnders-example.json");
      config.setTestReport("test_rapport.pdf");
      config.setTestAttachment1FileName("kyle_southpark.jpg");
      config.setTestAttachment2FileName("cartman_southpark.png");
      config.setTestAttachment3FileName("stan_southpark.jpg");
      config.setTestAttachment4FileName("kenny_southpark.png");
      
      String certificate = props.getProperty("certificate");
      String privatekey = props.getProperty("private_key");

      loadCertificateAndKeyFromFile(config, certificate, privatekey);
      if (Arrays.asList(args).contains("--json")) {
        config.setJsonOutput(true);
      }
      if (Arrays.asList(args).contains("--verify")) {
        config.setVerify(true);
      }
    } else {
      System.out.println("Usage: java -jar example-client.jar <argument>");
      System.out.println("Arguments:");
      System.out.println("  --json: Only print the token request");
      System.out.println("  --verify: Only verify the JWT grant");
      System.exit(0);
    }

    return config;
  }

  private static void loadCertificateAndKeyFromFile(Configuration config, String certificate,
      String privateKey) throws Exception {

    final InputStream is = new FileInputStream(certificate);
    CertificateFactory fac = CertificateFactory.getInstance("X509");
    X509Certificate cert = (X509Certificate) fac.generateCertificate(is);

    byte[] keyBytes = Files.readAllBytes(Paths.get(privateKey));
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    PrivateKey key = keyFactory.generatePrivate(spec);

    config.setCertificate(cert);
    config.setPrivateKey(key);
  }

  private static Properties readPropertyFile(String filename) throws Exception {
    Properties props = new Properties();

    InputStream inputStream = new FileInputStream(filename);
    props.load(inputStream);

    return props;
  }
}

