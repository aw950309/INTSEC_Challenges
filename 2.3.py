# Challenge 2.3 (Normal): Send me an email encrypted with PGP
#     This challenge is a practical exercise in using asymmetric cryptography with PGP (Pretty Good Privacy) to send a secure email (Challenges Last updated 2025-11-12.pdf, p. 1; Cryptography 2.pdf, p. 65).
#
# Step-by-Step Guide:
#
# Install PGP Software: You need a tool that can handle PGP encryption. A common one is GnuPG (GPG). You might also use an email client with PGP integration, like Thunderbird with the Enigmail/OpenPGP add-on.
#
# Generate Your Own Key Pair: Create your own public and private PGP key pair.
#
# gpg --full-generate-key
# Follow the prompts. Choose RSA, a key size (e.g., 4096 bits), an expiration date, and provide your name and email address. You will also set a passphrase to protect your private key.
# Get the Instructor's Public Key: Download the instructor's public key from NextILearn as instructed.
#
# Import the Instructor's Public Key: Add the instructor's key to your keyring so you can use it to encrypt messages for them.
#
# gpg --import /path/to/instructors_key.asc
# Find a Source on "Web of Trust": Read about the PGP Web of Trust concept. It's a decentralized trust model used to verify the authenticity of public keys. Find an article or a good source that explains it and get the link.
#
# Compose the Email: Write an email that includes:
#
# The link to the source on Web of Trust you found.
# Your own public key, so the instructor can reply securely. You can export your key using gpg --armor --export YOUR_EMAIL.
# Encrypt the Email: Use the instructor's public key to encrypt the body of your email. Your PGP software or email client will handle this. The subject line should not be encrypted.
#
# Subject: [INTSEC] Challenge 2.3
# Send the Email: Send the encrypted email to the instructor.
#
# Upload Your Public Key: Upload your public key to a public keyserver as instructed.
#
# gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
# Receive and Decrypt the Reply: The instructor will reply with an email encrypted using your public key. You will need to use your private key (and its passphrase) to decrypt it. The decrypted message will contain the secret answer for the challenge.
#
# This step-by-step guide should simplify the process for tackling the lecture 2 challenges. Good luck