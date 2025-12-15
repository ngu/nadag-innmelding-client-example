package no.ngu.oauth2.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonElement;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.Console;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ExampleClient {
  private static Configuration config;
  private static HttpClient client;

  public static void main(String[] args) throws Exception {
    config = Configuration.load(args);
    Console console = System.console();

    String jwt = makeJwt(config);
    if (config.getJsonOutput()) {
      ObjectMapper mapper = new ObjectMapper();
      Map<String, Object> output = new HashMap<>();
      output.put("grant", jwt);
      if (config.hasTokenEndpoint()) {
        output.put("token", mapper.readValue(makeTokenRequest(jwt, config), Object.class));
      }
      System.out.println(mapper.writeValueAsString(output));
    } else {
      System.out.println("Generated JWT-grant:");
      System.out.println(jwt);

      String response = "";

      if (config.hasTokenEndpoint()) {
        System.out.println("\nRetrieved token-response:");
        response = makeTokenRequest(jwt, config);
        System.out.println(response);
      }
      if (config.getVerify()) {
        JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();

        client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(config.getVerificationEndpoint())).build();

        HttpResponse<String> maskinportenResponse = client.send(request, BodyHandlers.ofString());
        JsonObject maskinportenResponseJson = JsonParser.parseString(maskinportenResponse.body()).getAsJsonObject();

        boolean result;
        try {
          SignedJWT signedJWT = SignedJWT.parse(responseJson.get("access_token").getAsString());
          JWK key = JWK.parse(maskinportenResponseJson.getAsJsonArray("keys").get(0).toString());
          JWSVerifier verifier = new RSASSAVerifier(key.toRSAKey());
          result = signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
          result = false;
        }

        System.out.println("\nSignature verified: " + result);
      } else if (config.getTestFileName() != null) {

        boolean withErrors = false;
        String goOn = console.readLine("Continue uploading GU without errors (y/n)?: ");
        if (goOn.equals("y") || goOn.equals("Y")) {
          withErrors = false;
          config.setTestFileName("GeotekniskUnders-example-ok.json");
        }
        else if (goOn.equals("n") || goOn.equals("N")) {
          withErrors = true;
        }
        else {
          System.exit(0);
        }

        FileInputStream inputStream = new FileInputStream(config.getTestFileName());
        String testFile = new String(inputStream.readAllBytes());
        inputStream.close();

        JsonObject testFileJson = JsonParser.parseString(testFile).getAsJsonObject();
        String eksternId = testFileJson.get("eksternIdentifikasjon").getAsJsonObject().get("eksternId").getAsString();
        testFileJson.get("eksternIdentifikasjon").getAsJsonObject().addProperty("eksternId", eksternId + " - " + UUID.randomUUID().toString());
        
        JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();
        String access_token = responseJson.get("access_token").getAsString();

        client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        URI uri = URI.create(config.getApiEndpoint() + "/auth/token/" + config.getUserId());
        HttpRequest request = HttpRequest.newBuilder().uri(uri).POST(BodyPublishers.ofString(access_token))
            .header("Content-Type", "text/plain").header("Accept", "text/plain").build();

        HttpResponse<String> authResponse = client.send(request, BodyHandlers.ofString());
        System.out.println("Auth response: " + authResponse.statusCode());
        System.out.println("Auth response body: " + authResponse.body());

        if (withErrors) {
          goOn = console.readLine("Continue uploading attatchment one (y/n)?: ");
          if (!goOn.equals("y") && !goOn.equals("Y")) {
            System.exit(0);
          }

          UUID attachment1Id = createGb(null, config.getAttachment1TestFileName(), authResponse.body(), "image/jpeg");

          goOn = console.readLine("Continue uploading GU (y/n)?: ");
          if (!goOn.equals("y") && !goOn.equals("Y")) {
            System.exit(0);
          }

          UUID attachment2Id = UUID.randomUUID();
          testFileJson.get("harDokument").getAsJsonArray().get(0).getAsJsonObject().addProperty("dokumentID", attachment1Id.toString());
          testFileJson.get("harDokument").getAsJsonArray().get(1).getAsJsonObject().addProperty("dokumentID", attachment2Id.toString());

          HttpResponse<String> guResponse = createGu(testFileJson, authResponse.body(), "epsg_4326");

          if (guResponse.statusCode() == 200) {
            JsonObject guResponseJson = JsonParser.parseString(guResponse.body()).getAsJsonObject();
            JsonObject guIdentification = guResponseJson.get("geotekniskUnders").getAsJsonObject().get("identifikasjon").getAsJsonObject();
            JsonArray guDiagnostics = guResponseJson.get("diagnostics").getAsJsonObject().get("diagnostics").getAsJsonArray();
            JsonArray guUndersPkt = guResponseJson.get("geotekniskUnders").getAsJsonObject().get("undersPkt").getAsJsonArray();
            
            boolean guFatal = false;
            for (JsonElement diag : guDiagnostics) {
              if (diag.getAsJsonObject().get("severity").getAsString().equals("FATAL")) {
                guFatal = true;
              }
            }
            
            System.out.println("GU insert identifikasjon: " + guIdentification);
            System.out.println("GU insert undersPkt count: " + guUndersPkt.size());
            System.out.println("GU insert diagnostics count: " + guDiagnostics.size());
            if (guFatal) System.out.println("GU insert diagnostics has FATAL errors!");

            goOn = console.readLine("Continue uploading attatchment two (y/n)?: ");
            if (!goOn.equals("y") && !goOn.equals("Y")) {
              System.exit(0);
            }

            createGb(attachment2Id.toString(), config.getAttachment2TestFileName(), authResponse.body(), "image/png");

            goOn = console.readLine("Continue updating GU (three times) (y/n)?: ");
            if (!goOn.equals("y") && !goOn.equals("Y")) {
              System.exit(0);
            }

            String guLokalId = guIdentification.get("lokalId").getAsString();

            for (int i = 0; i < 3; ++i) {
              guResponseJson.get("geotekniskUnders").getAsJsonObject().get("undersPkt").getAsJsonArray().remove(0);
              HttpResponse<String> guUpdateResponse = updateGu(guLokalId, guResponseJson.get("geotekniskUnders").getAsJsonObject(), authResponse.body(), "epsg_4326");
              System.out.println("GU update response: " + guUpdateResponse.statusCode());
              JsonObject guUpdateResponseJson = JsonParser.parseString(guUpdateResponse.body()).getAsJsonObject();
              JsonArray guUpdateDiagnostics = guUpdateResponseJson.get("diagnostics").getAsJsonObject().get("diagnostics").getAsJsonArray();
              JsonArray guUpdateUndersPkt = guUpdateResponseJson.get("geotekniskUnders").getAsJsonObject().get("undersPkt").getAsJsonArray();

              guFatal = false;
              for (JsonElement diag : guUpdateDiagnostics) {
                if (diag.getAsJsonObject().get("severity").getAsString() == "FATAL") {
                  guFatal = true;
                }
              }

              System.out.println("GU update undersPkt count: " + guUpdateUndersPkt.size());
              System.out.println("GU update diagnostics count: " + guUpdateDiagnostics.size());
              if (guFatal) System.out.println("GU update diagnostics has FATAL errors!");
            }
          }
        }
        else {
          goOn = console.readLine("Continue uploading attatchments (y/n)?: ");
          if (!goOn.equals("y") && !goOn.equals("Y")) {
            System.exit(0);
          }

          UUID attachment1Id = createGb(null, config.getTestReport(), authResponse.body(), "application/pdf");
          testFileJson.get("harDokument").getAsJsonArray().get(0).getAsJsonObject().addProperty("dokumentID", attachment1Id.toString());

          UUID attachment2Id = createGb(null, config.getAttachment1TestFileName(), authResponse.body(), "image/jpeg");
          testFileJson.get("undersPkt").getAsJsonArray().get(0).getAsJsonObject().get("harDokument").getAsJsonArray().get(0).getAsJsonObject().addProperty("dokumentID", attachment2Id.toString());

          UUID attachment3Id = createGb(null, config.getAttachment2TestFileName(), authResponse.body(), "image/png");
          testFileJson.get("undersPkt").getAsJsonArray().get(0).getAsJsonObject().get("harUndersøkelse").getAsJsonArray().get(0).getAsJsonObject().get("harDokument").getAsJsonArray().get(0).getAsJsonObject().addProperty("dokumentID", attachment3Id.toString());

          goOn = console.readLine("Continue uploading GU (y/n)?: ");
          if (!goOn.equals("y") && !goOn.equals("Y")) {
            System.exit(0);
          }

          HttpResponse<String> guResponse = createGu(testFileJson, authResponse.body(), "epsg_4326");

          if (guResponse.statusCode() == 200) {
            JsonObject guResponseJson = JsonParser.parseString(guResponse.body()).getAsJsonObject();
            JsonObject guIdentification = guResponseJson.get("geotekniskUnders").getAsJsonObject().get("identifikasjon").getAsJsonObject();
            JsonArray guDiagnostics = guResponseJson.get("diagnostics").getAsJsonObject().get("diagnostics").getAsJsonArray();
            JsonArray guUndersPkt = guResponseJson.get("geotekniskUnders").getAsJsonObject().get("undersPkt").getAsJsonArray();
            
            boolean guFatal = false;
            for (JsonElement diag : guDiagnostics) {
              if (diag.getAsJsonObject().get("severity").getAsString().equals("FATAL")) {
                guFatal = true;
              }
            }
            
            System.out.println("GU insert identifikasjon: " + guIdentification);
            System.out.println("GU insert undersPkt count: " + guUndersPkt.size());
            System.out.println("GU insert diagnostics count: " + guDiagnostics.size());
            if (guFatal) System.out.println("GU insert diagnostics has FATAL errors!");
          }
        } 
      }
    }
  }

  private static UUID createGb(String gbId, String filename, String authToken, String mimeType) throws Exception {
    FileInputStream attachmentInputStream = new FileInputStream(filename);

    URI uri = URI.create(config.getVedleggEndpoint() + "/vedlegg" + (gbId == null ? "" : "/" + gbId) + "?name=" + filename + "&mimeType=" + mimeType);
    HttpRequest request = HttpRequest.newBuilder().uri(uri).POST(BodyPublishers.ofByteArray(attachmentInputStream.readAllBytes()))
        .header("Authorization", "Bearer " + authToken)
        .header("Content-Type", "application/octet-stream")
        .header("Accept", "application/json")
        .build();

    attachmentInputStream.close();
    HttpResponse<String> vedleggResponse = client.send(request, BodyHandlers.ofString());
      JsonObject vedleggResponseJson = JsonParser.parseString(vedleggResponse.body()).getAsJsonObject();
    System.out.println("Vedlegg id: " + vedleggResponseJson.get("uuid").getAsString());
    System.out.println("Vedlegg response: " + vedleggResponse.statusCode());

    return UUID.fromString(vedleggResponseJson.get("uuid").getAsString());
  }

  private static HttpResponse<String> createGu(JsonObject gu, String authToken, String epsgCode) throws Exception {
    URI uri = URI.create(config.getApiEndpoint() + "/v1/GeotekniskUnders?epsgCode=" + epsgCode);
    HttpRequest request = HttpRequest.newBuilder().uri(uri).POST(BodyPublishers.ofString(gu.toString()))
        .header("Authorization", "Bearer " + authToken)
        .header("Content-Type", "application/json").header("Accept", "application/json")
        .build();

    HttpResponse<String> guResponse = client.send(request, BodyHandlers.ofString());
    System.out.println("GU insert response: " + guResponse.statusCode());

    return guResponse;
  }

  private static HttpResponse<String> updateGu(String guId, JsonObject gu, String authToken, String epsgCode) throws Exception {
    URI uri = URI.create(config.getApiEndpoint() + "/v1/GeotekniskUnders/" +guId+  "?epsgCode=epsg_4326");

    HttpRequest request = HttpRequest.newBuilder().uri(uri).PUT(BodyPublishers.ofString(gu.toString()))
        .header("Authorization", "Bearer " + authToken)
        .header("Content-Type", "application/json").header("Accept", "application/json")
        .build();

    HttpResponse<String> guResponse = client.send(request, BodyHandlers.ofString());

    return guResponse;
  }

  private static String makeJwt(Configuration config) throws Exception {
    List<Base64> certChain = new ArrayList<>();
    certChain.add(Base64.encode(config.getCertificate().getEncoded()));

    JWSHeader jwtHeader;
    if (config.hasKid()) {
      jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(config.getKid()).build();
    } else {
      jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertChain(certChain).build();
    }

    // Mark: consumer_org must be unique for each grant and issue time must be in UTC
    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().audience(config.getAud()).issuer(config.getIss())
        .claim("consumer_org", config.getConsumerOrg()).jwtID(UUID.randomUUID().toString())
        .issueTime(new Date(Clock.systemUTC().millis()))
        .expirationTime(new Date(Clock.systemUTC().millis() + 120000));

    JWTClaimsSet claims = builder.build();

    JWSSigner signer = new RSASSASigner(config.getPrivateKey());
    SignedJWT signedJWT = new SignedJWT(jwtHeader, claims);
    signedJWT.sign(signer);

    return signedJWT.serialize();
  }

  private static String makeTokenRequest(String jwt, Configuration config) {
    StringBuilder formBodyBuilder = new StringBuilder();
    formBodyBuilder.append("grant_type=");
    formBodyBuilder.append(URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8));
    formBodyBuilder.append("&");
    formBodyBuilder.append("assertion=");
    formBodyBuilder.append(URLEncoder.encode(jwt, StandardCharsets.UTF_8));

    try {
      HttpClient client = HttpClient.newHttpClient();
      HttpRequest request = HttpRequest.newBuilder().uri(URI.create(config.getTokenEndpoint()))
          .POST(BodyPublishers.ofString(formBodyBuilder.toString()))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .build();

      HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

      return response.body();

    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
}
