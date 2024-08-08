from random import randint
import argparse
import hashlib
import sys
import os


def quiet_print(func):
    def print_wrapper(*args, **kwargs):
        sys.stdout = open(os.devnull, "w")
        value = func(*args, **kwargs)
        sys.stdout = sys.__stdout__
        return value
    return print_wrapper


def loud_print(func):
    def print_wrapper(*args, **kwargs):
        sys.stdout = sys.__stdout__
        value = func(*args, **kwargs)
        sys.stdout = open(os.devnull, "w")
        return value
    return print_wrapper


def password_generator(length: int, number: int, strength: int) -> list:
    passwords = []
    pword_string = ""
    lower_case = "abcdefghijklmnopqrstuvwxyz"
    upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "1234567890"
    symbols = "!@#$%^&*()"
    if strength == 0:
        pword_string = lower_case
    elif strength == 1:
        pword_string = lower_case + upper_case
    elif strength == 2:
        pword_string = lower_case + upper_case + numbers
    elif strength == 3:
        pword_string = lower_case + upper_case + numbers + symbols
    for _ in range(number):
        password = ""
        for _ in range(length):
            password += pword_string[randint(0, (len(pword_string) - 1))]
        passwords.append(password)
    print(f"{len(passwords)} passwords generated of strength {strength} using the characters: {pword_string}")
    return passwords


def hash_generator(passwords: list, hash_algo: str) -> list:
    hashed_passwords = []
    for password in passwords:
        hash = hashlib.new(hash_algo, password.encode('utf-8')).hexdigest()
        hashed_passwords.append(hash)
    print(f"{len(hashed_passwords)} hash(es) generated")
    return hashed_passwords


def input_file_reader(input_file: str, passwords: list) -> list:
    try:
        with open(input_file, "r") as ifile:
            for line in ifile:
                passwords.append(line)
            print(f"{len(passwords)} passwords read from file")
            return passwords
    except FileNotFoundError:
        print(f"Invalid file path provided for input file {input_file}")
        sys.exit()


def pass_file_writer(passwords: list, pass_file: str) -> bool:
    try:
        with open(pass_file, "a") as pfile:
                for password in passwords:
                    pfile.write(f"{password}\n")
                pfile.close()
        print(f"{len(passwords)} password(s) written to output file")
    except FileNotFoundError:
        print(f"Invalid file path provided for password file {args.pass_file}")
        sys.exit()  


def hash_file_writer(hashed_passwords: list, hash_file: str) -> bool:
    try:
        with open(hash_file, "a") as hfile:
                for hash in hashed_passwords:
                    hfile.write(f"{hash}\n")
                hfile.close()
        print(f"{len(hashed_passwords)} hashed password(s) written to output file")
    except FileNotFoundError:
        print(f"Invalid file path provided for hash file {args.hash_file}")
        sys.exit()  


def output_file_writer(passwords: list, hashed_passwords: list, pass_file: str, hash_file: str) -> bool:
    if pass_file != None:
        pass_file_writer(passwords, pass_file)
    if hash_file != None:
        hash_file_writer(hashed_passwords, hash_file)
    return True


# @loud_print
def hash_printer(hashed_passwords: list, hash_algo: str) -> bool:
    print(f"Generated {hash_algo} Hashes:")
    for hash in hashed_passwords:
        print(hash)
    return True


# @loud_print
def pass_printer(passwords: list) -> bool:
    print("Generated Passwords:")
    for password in passwords:
        print(password)
    return True


def console_printer(passwords: list, hashed_passwords: list, hash_algo: str) -> bool:
    if passwords:
        pass_printer(passwords)
    if hashed_passwords:
        hash_printer(hashed_passwords, hash_algo)
    return True


def main(args):
    passwords = []
    hashed_passwords = []
    length = args.length
    number = args.number
    strength = args.strength
    hash_algo = args.hash_algo
    pass_file = args.pass_file
    hash_file = args.hash_file
    input_file = args.input_file
    print_pass = args.print_pass
    print_hash = args.print_hash
    if input_file == None:
        print(f"Generating {number} password(s) of length {length} and strength {strength}")
        passwords = password_generator(length, number, strength)
    if input_file != None:
        print(f"Reading the password input file to hash the values")
        passwords = input_file_reader(input_file)
    if hash_algo != None:
        print(f"Generating {len(passwords)} password hash(es) using {hash_algo}")
        hashed_passwords = hash_generator(passwords, hash_algo)
    if pass_file != None or hash_file != None:
        print("Writing passwords and/or hashes to the output file")
        output_file_writer(passwords, hashed_passwords, pass_file, hash_file)
    if print_pass == 1:
        pass_printer(passwords)
    if print_hash == 1:
        hash_printer(hashed_passwords, hash_algo)
    if pass_file == None and hash_file == None:
        print("Printing passwords and/or hashes to console because no output files were specified")
        console_printer(passwords, hashed_passwords, hash_algo)
    

def arguement_validator(args):
    hashtypes = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake_128", "shake_256"]
    if args.length <= 0:
        print(f"Invalid integer provided for length of password unable to generate password(s) of length {args.length}")
        sys.exit()
    if args.number <= 0:
        print(f"Invalid integer provided for number of password(s) unable to generate {args.number} password(s)")
        sys.exit()
    if args.input_file != None and args.hash_algo == None:
        print("Unable to hash password(s) without hashing algorithm specified")
        sys.exit()
    if args.pass_file == None and args.print_pass == 0:
        print("Invalid options set for password output. Printing to console")
        args.print_pass = 1
    if args.hash_file == None and args.print_hash == 0:
        print("Invalid options set for hash output. Printing to console")
        args.print_hash = 1
    if args.hash_algo not in hashtypes:
        print(f"Hashing algorithm {args.hash_algo} provided is invalid")
        sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
    prog="\n\nPASSHASHGEN\n\n",
    description="A program that generates passwords of the specified length, number, and strength. The option to hash the password(s) and output either the hash/passwords/both to the specified text file(s) is available. It is also possible to read a text file of password(s) and convert them to a hash of specified type.",
    epilog="Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?"
    )
    parser.add_argument("-l", dest='length', type=int, action="store", default=8, help="Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used")
    parser.add_argument("-n", dest='number', type=int, action="store", default=1, help="Flag to set the number of password(s) to be generated. The default is 1 unless set")
    parser.add_argument("-s", dest='strength', type=int, action="store", default=3, help="Flag to set the strength of password generated. Set to strong(3) by default [0-3]")
    parser.add_argument("-m", dest='hash_algo', type=str, action="store", default=None, help="Flag to set the hashing method to complete on password(s). Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256. If not set no hashing will occur")
    parser.add_argument("-i", dest='input_file', type=str, default=None, help="Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set")
    parser.add_argument("-op", dest='pass_file', type=str, default=None, help="Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console")
    parser.add_argument("-oh", dest='hash_file', type=str, default=None, help="Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console")
    parser.add_argument("-pp", dest='print_pass', type=int, action="store", default=1, help="Flag to enable or disable whether the password(s) print to console. The default is to print the password(s) to console. Not possible to disable if no output file is provided. 1:Enabled 0:Disabled")
    parser.add_argument("-ph", dest='print_hash', type=int, action="store", default=1, help="Flag to enable or disable whether the hash(es) to console. Not possible to disable if no output files are provided. The default is to print the hashes to console 1:Enabled 0:Disabled")
    parser.add_argument("-q", dest='quiet', type=int, action="store", default=0, help="Flag to enable or disable whether the status messages print to console other than hash or passwords. The default is to print status to console 1:Enabled 0:Disabled")
    args = parser.parse_args()
    print("Starting password generation and/or hashing process")
    arguement_validator(args)
    if args.quiet == 1:
        quiet_print(main(args))
    else:
        main(args)
    print("Password and/or hash generation process is complete")