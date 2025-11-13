# Ciphertext från challenge 1.1
ciphertext = "D_AZ_5H7S006_9WHF6BHD_33HX_5VHSAH3WS0AHIJHX3SY0H064WH6XHAZW4HS9WHX_3WH5S4WVHX3SYH5HTBAH064WA_4W0HAZWHX3SYH_0HZ_VVW5H_5HS56AZW9HX_3WHAZ_0H4W00SYWH_0HAZWHS50DW9HA6HUZS33W5YWHIHV6AHI"

# Definiera alfabetet som används i ciphern
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890"
n = len(alphabet)

# Funktion för att dekryptera med en given nyckel
def decrypt(ciphertext, key):
    plaintext = ''.join(
        alphabet[(alphabet.index(char) + key) % n]
        for char in ciphertext
    )
    return plaintext.replace('_', ' ')

# Generera alla möjliga plaintexts
possible_plaintexts = [(key, decrypt(ciphertext, key)) for key in range(1, n)]

# Filtrera ut läsbara texter
readable = [pt for pt in possible_plaintexts if any(word in pt[1] for word in ["THE", "AND", "YOU"])]

print(readable)