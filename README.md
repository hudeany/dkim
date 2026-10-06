# dkim

[![Maven Central](https://img.shields.io/maven-central/v/de.soderer/dkim?label=Maven%20Central)](https://central.sonatype.com/artifact/de.soderer/dkim)

**Creation and verification of DKIM email signatures (DomainKeys Identified Mail) in Java**

Sign outgoing emails with DKIM (RFC 6376) and verify the DKIM signatures of received emails, based on Jakarta Mail. Signatures created by this library are verified by common mail servers and by independent implementations like dkimpy.

## Features

- Signing with `rsa-sha256` and canonicalization `relaxed` or `simple` for header and body
- `DkimSignedMessage` as drop-in replacement for `MimeMessage`, signing happens automatically when the message is sent
- Only the headers, which are actually written, are signed (e.g. `Bcc` is excluded when sending)
- Optional signing identity (`i=`) and headers excluded from signing
- Verification of all DKIM signatures of a message (multiple signatures as defined in RFC 6376)
- Check of the signing domain against the From domain (as used by DMARC, default) or the Return-Path domain
- Detailed verification result per signature, including the reason of failed verifications
- Support of over-signed headers, `x=` (expiration), `l=` (body length) and key record flags
- Public keys are retrieved from DNS with timeouts and cached (configurable time to live)

## Requirements

- Java 11 or higher
- Jakarta Mail 2.x: API (`jakarta.mail:jakarta.mail-api`) and an implementation, e.g. [Eclipse Angus Mail](https://mvnrepository.com/artifact/org.eclipse.angus/angus-mail) (`org.eclipse.angus:angus-mail`)

## Maven

This library is available on [Maven Central](https://central.sonatype.com/artifact/de.soderer/dkim). The current version is shown in the badge above.

```xml
<dependency>
	<groupId>de.soderer</groupId>
	<artifactId>dkim</artifactId>
	<version>x.y.z</version>
</dependency>
```

## Usage

### Creating a key pair and the DNS record

```bash
# Private key (PKCS#8), used for signing
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dkim_private.pem

# Public key for the DNS record
openssl pkey -in dkim_private.pem -pubout -outform DER | base64 -w0
```

Publish the public key as TXT record `<selector>._domainkey.<domain>`, e.g. for selector `mail` and domain `example.com`:

```
mail._domainkey.example.com.  IN TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
```

### Signing and sending an email

```java
// Load the private key (PKCS#8 PEM)
final String pem = new String(Files.readAllBytes(Paths.get("dkim_private.pem")), StandardCharsets.US_ASCII)
	.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "")
	.replaceAll("\\s", "");
final RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
	.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));

final Properties properties = new Properties();
properties.put("mail.smtp.host", "smtp.example.com");
final Session session = Session.getInstance(properties);

// null as Message-ID: Jakarta Mail generates one
final DkimSignedMessage message = new DkimSignedMessage(session, null);
message.setFrom(new InternetAddress("sender@example.com"));
message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient@example.org"));
message.setSubject("DKIM signed message");
message.setText("Hello World", "UTF-8");

// Signing domain, selector, private key and optional identity
message.setDkimKeyData("example.com", "mail", privateKey, null);

// Optional: canonicalization (default relaxed/relaxed) and headers not to sign
message.setCanonicalization(true, true);
message.setExcludedHeaders("Return-Path");

Transport.send(message);
```

`DkimSignedMessage` is used like a normal `MimeMessage`, e.g. with multipart content and attachments. The signature is created when the message is written, so all parts must be added before sending.

### Checking the DKIM signature of a received email

```java
final MimeMessage receivedMessage = new MimeMessage(session, new FileInputStream("received.eml"));

final Boolean result = DkimUtilities.checkDkimSignature(receivedMessage);
if (result == null) {
	System.out.println("Message is not signed");
} else if (result) {
	System.out.println("Valid DKIM signature");
} else {
	System.out.println("Invalid DKIM signature");
}
```

`checkDkimSignature` accepts a message, if at least one signature is valid and its signing domain matches the domain of the From header, as DMARC does. `verifyDkimSignature` does the same, but throws an exception with the reasons of a failed verification.

### Detailed verification of all signatures

```java
final DkimVerificationResult result = DkimUtilities.verifyDkimSignatures(receivedMessage, DkimUtilities.DomainAlignment.NONE);

System.out.println("Signed: " + result.isSigned());
System.out.println("Valid: " + result.isValid());
System.out.println("Valid signing domains: " + result.getValidDomains());
for (final DkimSignatureResult signatureResult : result.getSignatureResults()) {
	System.out.println(signatureResult);
}
```

`DomainAlignment` defines, which domain a valid signature must match. The signing domain (`d=`) must be the same domain or a parent domain:

| Value | Required domain |
|---|---|
| `FROM` (default) | Domain of the From header, which is shown to the recipient, as used by DMARC |
| `RETURN_PATH` | Domain of the Return-Path header (envelope sender, bounce address) |
| `NONE` | Any signing domain is accepted, use `getValidDomains()` to decide yourself |

At most 10 signatures of a message are verified (`DkimUtilities.MAXIMUM_SIGNATURES_TO_VERIFY`), because each signature may need a DNS lookup.

### DNS key cache

Retrieved public keys are cached for 2 hours by default:

```java
DkimUtilities.setCacheTtl(30 * 60 * 1000); // 30 minutes, 0 disables caching
DkimUtilities.clearDomainKeyCache();
```
