lowercase = 'abcdefghijklmnopqrstuvwxyz'
uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def encrypt(plaintext, key):
    ciphertext = ''

    for letter in plaintext:
        
        if letter == ' ':
            ciphertext += ' '
            continue

        if letter in lowercase:
             index = lowercase.find(letter)
             new_index = index + key
             if new_index >= 26:
                new_index -= 26
             ciphertext += lowercase[new_index]

        elif letter in uppercase:
            index = uppercase.find(letter)

            new_index = index + key
            if new_index >= 26:
                new_index -= 26

            ciphertext += uppercase[new_index]

        else:
             ciphertext +=letter
    return ciphertext



def decrypt(ciphertext, key):
    plaintext = ''

    for letter in ciphertext:

            
        if letter == ' ':
            plaintext += ' '
            continue
        if letter in lowercase:
            index = lowercase.find(letter)

            new_index = index - key
                
            if new_index < 0:
                new_index += 26

            plaintext += lowercase[new_index]

        elif letter in uppercase:
            index = uppercase.find(letter)

            new_index = index - key

            if new_index <0:
                new_index +=26
            plaintext += uppercase[new_index]

        else:
            plaintext += letter

    return plaintext



print()
print("*** CAESAR CIPHER ***")
print()

print('Do you want to encrypt or decrypt?')
user_input = input('e/d: ').lower()
print()

if user_input == 'e':

    print('ENCRYPYTION MODE SELECTED')
    print()

    key = int(input('Enter the key(1 through 26): '))
    text = input('Enter the text to encrypt: ')

    ciphertext = encrypt(text,key)

    print(f'CIPHERTEXT: {ciphertext}')

elif user_input == 'd':

    print('DECRYPYTION MODE SELECTED')
    print()

    key = int(input('Enter the key(1 through 26): '))
    text = input('Enter the text to decrypt: ')

    plaintext = decrypt(text, key)

    print(f'PLAINTEXT: {plaintext}')

else:
     print("Invalid option. Please choose e or d.")