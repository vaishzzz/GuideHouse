# encoding=utf8
import ast
from random import *
from pprint import pprint


def encrypt_data(plaintext, userPass):
    passwordsToSeeds = {}  # dictionary
    seedsToMessages = {}  # dictionary
    trueSeed = randint(10, 27)  # Random seed value
    states = {  # U.S States as secret messages
        'AK': 'Alaska',
        'AL': 'Alabama',
        'AR': 'Arkansas',
        'AS': 'American Samoa',
        'AZ': 'Arizona',
        'CA': 'California',
        'CO': 'Colorado',
        'CT': 'Connecticut',
        'DC': 'District of Columbia',
        'DE': 'Delaware',
        'FL': 'Florida',
        'GA': 'Georgia',
        'GU': 'Guam',
        'HI': 'Hawaii',
        'IA': 'Iowa',
        'ID': 'Idaho',
        'IL': 'Illinois',
        'IN': 'Indiana',
        'KS': 'Kansas',
        'KY': 'Kentucky',
        'LA': 'Louisiana',
        'MA': 'Massachusetts',
        'MD': 'Maryland',
        'ME': 'Maine',
        'MI': 'Michigan',
        'MN': 'Minnesota',
        'MO': 'Missouri',
        'MP': 'Northern Mariana Islands',
        'MS': 'Mississippi',
        'MT': 'Montana',
        'NA': 'National',
        'NC': 'North Carolina',
        'ND': 'North Dakota',
        'NE': 'Nebraska',
        'NH': 'New Hampshire',
        'NJ': 'New Jersey',
        'NM': 'New Mexico',
        'NV': 'Nevada',
        'NY': 'New York',
        'OH': 'Ohio',
        'OK': 'Oklahoma',
        'OR': 'Oregon',
        'PA': 'Pennsylvania',
        'PR': 'Puerto Rico',
        'RI': 'Rhode Island',
        'SC': 'South Carolina',
        'SD': 'South Dakota',
        'TN': 'Tennessee',
        'TX': 'Texas',
        'UT': 'Utah',
        'VA': 'Virginia',
        'VI': 'Virgin Islands',
        'VT': 'Vermont',
        'WA': 'Washington',
        'WI': 'Wisconsin',
        'WV': 'West Virginia',
        'WY': 'Wyoming'
    }
    ' Verify input with the user '
    print("Your password is :" + userPass
          + ", your seed value is :" + str(trueSeed)
          + ", and your secret message is :" + plaintext
          + "\n=====================================")

    passwordsToSeeds[userPass] = trueSeed
    seedsToMessages[trueSeed] = plaintext

    passwordsToSeeds[userPass + str(trueSeed - 1)] = trueSeed + 1
    seedsToMessages[trueSeed + 1] = states['AL']

    passwordsToSeeds[userPass + str(trueSeed - 2) + "1"] = trueSeed + 2
    seedsToMessages[trueSeed + 2] = states['CA']

    passwordsToSeeds[userPass.lower()] = trueSeed + 3
    seedsToMessages[trueSeed + 3] = states['FL']

    passwordsToSeeds[userPass.lower() + str(trueSeed + 1) + "3"] = trueSeed + 4
    seedsToMessages[trueSeed + 4] = states['TX']

    passwordsToSeeds[userPass.upper()] = trueSeed + 5
    seedsToMessages[trueSeed + 5] = states['TN']

    passwordsToSeeds[userPass.upper() + str(trueSeed + 2) + "5"] = trueSeed + 6
    seedsToMessages[trueSeed + 6] = states['WA']
    # ENCRYPTION: c = sk XOR sm
    cipher = int(passwordsToSeeds[userPass]) ^ trueSeed
    # Shuffle the passwords and display them on the screen to begin the game
    passwords = list(passwordsToSeeds.keys())
    shuffle(passwords)                   # Shuffle the passwords
    pprint(passwords)                    # Display results
    cipher = str(cipher) + ',' + str(trueSeed)
    # write data in a file.
    with open('StopGuessApp/Upload/data.txt', 'w') as data_file:
        data_file.write(str(seedsToMessages))
    data_file.close()
    # write password in a file.
    with open('StopGuessApp/Upload/pwd.txt', 'w') as pass_file:
        pass_file.write(str(passwordsToSeeds))
    pass_file.close()
    return cipher


def decrypt_data(ciphertext, userPass, trueSeed):
    try:
        with open('StopGuessApp/Upload/data.txt') as data_file:
            data = data_file.read()
        data_file.close()
        # reconstructing the data as a dictionary
        seedsToMessages = ast.literal_eval(data)

        with open('StopGuessApp/Upload/pwd.txt') as pass_file:
            pwd = pass_file.read()
        pass_file.close()
        # reconstructing the data as a dictionary
        passwordsToSeeds = ast.literal_eval(pwd)

        keySeed = passwordsToSeeds[userPass]
        # DECRYPTION: m = sk XOR c
        m = keySeed ^ ciphertext        # ^ == XOR
        if m != trueSeed:               # Honey checker
            print("Intruder! Sound alarm!")
        # Check seeds
        pprint(seedsToMessages[m])
        return seedsToMessages[m]
    except KeyError:
        print("Password not found. ")
        return b''


if __name__ == "__main__":
    userPass = input("Please enter a password: ")
    file = open("test.txt", "r")
    message = file.read()
    file.close()
    cipher_data = encrypt_data(message, userPass)
    print(cipher_data)
    honey_words = cipher_data.split(',')
    ciphertext = int(honey_words[0])
    trueSeed = int(honey_words[1])
    org_data = decrypt_data(ciphertext, userPass, trueSeed)
    print("org :", org_data)