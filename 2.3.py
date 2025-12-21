"""
Challenge 2.3 (Normal): Send me an email encrypted with PGP:

Read about Web of Trust.

Get my public key from NextILearn.

Send me an email (encrypted with my public key) including a link to a source on Web of Trust and your public key. (You can find my key on ILearn.)

    The email's subject must be "[INTSEC] Challenge 2.3".

    Please use the ascii armored format (.asc) rather than the binary format (.gpg).

Upload your public key on https://keyserver.ubuntu.com

I will answer you using your public key, giving you the secret to put as an answer for the challenge.
Make sure that you use the email address associated with your key! (and not a different one).


What I DID:

1. brew install gnupg

2. gpg --import /Users/alexwagner/Kod/GitHub/INTSEC_Challenges/PGP-public-key-nicolas-harrand.asc

gpg: directory '/Users/alexwagner/.gnupg' created
gpg: /Users/alexwagner/.gnupg/trustdb.gpg: trustdb created
gpg: key 087A2A0AF710B6B5: public key "Nicolas Harrand <nicolas.harrand@dsv.su.se>" imported
gpg: Total number processed: 1
gpg:               imported: 1

3. cd /Users/alexwagner/Kod/GitHub/INTSEC_Challenges

4. Passphrase: kattochhund!"

gpg: directory '/Users/alexwagner/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/Users/alexwagner/.gnupg/openpgp-revocs.d/A715CEA6F114EE63003E60814DC12483424975F7.rev'
public and secret key created and signed.

pub   rsa4096 2025-11-26 [SC]
      A715CEA6F114EE63003E60814DC12483424975F7
uid                      Alex Wagner (INTSEC-Key) <aw950309@gmail.com>
sub   rsa4096 2025-11-26 [E]

5. gpg --export --armor aw950309@gmail.com > my-public-key.asc

6. Created message.txt with the following content:
echo "Hello Nicolas. Here is a link to a source on the Web of Trust: https://en.wikipedia.org/wiki/Web_of_trust . Also, here is my public key: " > message.txt

cat my-public-key.asc >> PGP-public-key-alex-wagner.asc




"""