# Define your variables
ORIGINAL_MESSAGE="I give you the following amount of SEK coded in binary:\x12"
ORIGINAL_HMAC="67452301EFCDAB8998BADCFE10325476C3D2E1F0"
KEY_LENGTH=7
DATA_TO_APPEND="\x34" # Example extension

# Run the tool
# The tool will take the original HMAC as the internal state of SHA-1
# and continue hashing from there with your appended data.

# hash_extender --data "\$ORIGINAL_MESSAGE" \
#               --signature "\$ORIGINAL_HMAC" \
#               --key-length \$KEY_LENGTH \
#               --append "\$DATA_TO_APPEND" \
#                --format sha1

# The tool will output:
# 1. The new, valid HMAC (the answer for the "valid HMAC" part).
# 2. The full extended message, which includes the original message + padding + your appended data (the answer for the "extended message" part).