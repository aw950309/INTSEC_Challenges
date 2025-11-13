# Ciphertext från challenge
ciphertext = "D_AZ_5H7S006_9WHF6BHD_33HX_5VHSAH3WS0AHIJHX3SY0H064WH6XHAZW4HS9WHX_3WH5S4WVHX3SYH5HTBAH064WA_4W0HAZWHX3SYH_0HZ_VVW5H_5HS56AZW9HX_3WHAZ_0H4W00SYWH_0HAZWHS50DW9HA6HUZS33W5YWHIHV6AHI"

# Definiera alfabetet som används i ciphern
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

# Längd på alfabetet
n = len(alphabet)

# Loopar igenom alla möjliga shift-nycklar
for key in range(1, n):
    plaintext = ""
    for char in ciphertext:
        if char in alphabet:
            # Hitta positionen i alfabetet
            index = alphabet.index(char)
            # Flytta bakåt med nyckeln, wrap-around med modulo
            new_index = (index - key) % n
            plaintext += alphabet[new_index]
        else:
            # Behåll tecken som inte finns i alfabetet
            plaintext += char
    print(f"Key {key}: {plaintext}")
