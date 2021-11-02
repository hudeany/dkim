# DKIM signatures (JAVA)
Generation and validation of DKIM email signatures (DomainKeys Identified Mail) in JAVA

This example code needs following dependencies:
- activation-1.1.jar
- javax.mail-1.6.2.jar

The main function for generation of DKIM signatures is in
- DkimSignedMessage

Use Transport.send(mimeMessage) for sending this message after adding all your message parts

The main function for validation of DKIM signatures is in
- DkimUtilities.checkDkimSignature(Message)
