import hashlib

# Given data for all messages
KEY_1 = "1234"
KEY_2 = "5678"

MESSAGE_1 = "Challenge 2.2 is easy."
PROVIDED_HMAC_1 = "12d44a1c2448cc54ddffc75e69313a7964d5d775"

# Step 1: Calculate the inner hash: h(key_1 | msg)
# Note: Ensure you are encoding strings to bytes, as hash functions operate on bytes.
inner_data_1 = KEY_1.encode('ascii') + MESSAGE_1.encode('ascii')
inner_hash_1 = hashlib.sha1(inner_data_1).hexdigest()

# Step 2: Calculate the outer hash: h(key_2 | inner_hash)
# The inner hash is used as an ASCII string for the outer hash calculation
outer_data_1 = KEY_2.encode('ascii') + inner_hash_1.encode('ascii')
calculated_hmac_1 = hashlib.sha1(outer_data_1).hexdigest()

# Step 3: Compare
if calculated_hmac_1 == PROVIDED_HMAC_1:
    print("Message 1 is NOT tampered with.")
else:
    print("Message 1 HAS BEEN tampered with.")

# --- Repeat the process for Message 2 and Message 3 ---