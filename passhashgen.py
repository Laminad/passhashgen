from datetime import datetime
from random import randint
import platform
import argparse
import logging
import hashlib
import sys
import os


def argument_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="\n\nPassHashGen\n\n",
        formatter_class = argparse.MetavarTypeHelpFormatter,
        description="A program that generates passwords of the specified length, number, and strength with the ability to hash the password(s) after generating. If output file(s) is/are provided the hash/passwords/both will be written to the file. If an input file of password(s) is provided it will convert them to a hash of specified type.",
        epilog="Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?"
    )
    parser.add_argument("-l", dest='length', type=int, action="store", default=8, help="Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used")
    parser.add_argument("-n", dest='number', type=int, action="store", default=1, help="Flag to set the number of passwords to be generated. If not set default of 1 will be used")
    parser.add_argument("-s", dest='strength', type=int, action="store", default=3, help="Flag to set the strength of passwords generated. Set to strong(3) by default [0-3]")
    parser.add_argument("-m", dest='hash_algo', type=str, action="store", default=None, help="Flag to set the hashing method to complete on password(s). If not set no hashing will occur. Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256.")
    parser.add_argument("-i", dest='input_file', type=str, action="store", default=None, help="Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set")
    parser.add_argument("-op", dest='pass_file', type=str, action="store", default=None, help="Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console")
    parser.add_argument("-oh", dest='hash_file', type=str, action="store", default=None, help="Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console")
    parser.add_argument("-np", dest='print_pass', action="store_false", default=True, help="Flag to enable whether the password(s) print to console. The default is to print the password(s) to console unless textfile provided.")
    parser.add_argument("-nh", dest='print_hash', action="store_false", default=True, help="Flag to enable whether the hash(es) print to console. The default is to print the hash(es) to console unless textfile provided.")
    parser.add_argument("-v", dest='verbose', action="store_true", default=False, help="Flag to enable verbose status messages to console other than hash(es) or password(s). The default is not to print status to console.")
    args = parser.parse_args()
    return args


def argument_validator(args: argparse.Namespace) -> bool:
    hashtypes = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake_128", "shake_256"]
    if args.length <= 0:
        logger.error(f"Invalid integer provided for length of password unable to generate password(s) of length {args.length}")
        sys.exit()
    if args.number <= 0:
        logger.error(f"Invalid integer provided for number of password(s) unable to generate {args.number} password(s)")
        sys.exit()
    if args.hash_algo not in hashtypes:
        logger.error(f"Hashing algorithm {args.hash_algo} provided is invalid")
        sys.exit()
    if args.input_file != None and args.hash_algo == None:
        logger.error("Unable to hash password(s) without hashing algorithm specified")
        sys.exit()
    if args.hash_file == None and args.print_hash == False and args.hash_algo != None:
        logger.warning("Invalid options set for hash output. Printing to console")
        args.print_hash = True
    if args.pass_file == None and args.print_pass == False:
        logger.warning("Invalid options set for password output. Printing to console")
        args.print_pass = True
    return True


def logging_factory() -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(10) # Debug
    return logger


def log_directory_validator() -> str:
    if "Windows" in platform.platform():
        if not os.path.exists("C:\\ProgramData\\passhashgen"):
            os.makedirs("C:\\ProgramData\\passhashgen")
        file_path = os.path.realpath("C:\\ProgramData\\passhashgen\\phg_log_{:%Y-%m-%d}.log".format(datetime.now()))
    if "Linux" in platform.platform():
        if not os.path.exists("/var/log/passhashgen"):
            os.makedirs("/var/log/passhashgen")
        file_path = os.path.realpath("/var/log/passhashgen/phg_log_{:%Y-%m-%d}.log".format(datetime.now()))
    if "macOS" in platform.platform():
        if not os.path.exists("/var/log/passhashgen"):
            os.makedirs("/var/log/passhashgen")
        file_path = os.path.realpath("/var/log/passhashgen/phg_log_{:%Y-%m-%d}.log".format(datetime.now()))
    return file_path


def logfile_handler(logger: logging.Logger) -> logging.Logger:
    file_path = log_directory_validator()
    logfile = logging.FileHandler(file_path, 'a')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', "%Y-%m-%d %H:%M:%S")
    logfile.setFormatter(formatter)
    logger.addHandler(logfile)
    return logger


def console_streamer(logger: logging.Logger) -> logging.Logger:
    console = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', "%Y-%m-%d %H:%M:%S")
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger


def verbose_logger(args: argparse.Namespace, logger: logging.Logger) -> logging.Logger:
    if args.verbose == True:
        logger = console_streamer(logger)
        logger = logfile_handler(logger)
    else:
        logger = logfile_handler(logger)
    return logger


def pword_string_generator(strength: int) -> str:
    pword_string = ""
    numbers = "1234567890"
    lower_case = "abcdefghijklmnopqrstuvwxyz"
    upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    symbols = "!@#$%^&*()"
    if strength == 0:
        pword_string = numbers
    elif strength == 1:
        pword_string = numbers + lower_case
    elif strength == 2:
        pword_string = numbers + lower_case + upper_case
    elif strength == 3:
        pword_string = numbers + lower_case + upper_case + symbols
    return pword_string


def password_generator(length: int, number: int, pword_string: str) -> list:
    passwords = []
    for _ in range(number):
        password = ""
        for _ in range(length):
            password += pword_string[randint(0, (len(pword_string) - 1))]
        passwords.append(password)
    return passwords


def input_file_reader(input_file: str, passwords: list) -> list:
    try:
        with open(input_file, "r") as ifile:
            for line in ifile:
                passwords.append(line)
            return passwords
    except FileNotFoundError:
        logger.error(f"Invalid file path provided for input file {input_file}")
        sys.exit()


def hash_generator(passwords: list, hash_algo: str) -> list:
    hashed_passwords = []
    for password in passwords:
        hash = hashlib.new(hash_algo, password.encode('utf-8')).hexdigest()
        hashed_passwords.append(hash)
    return hashed_passwords


def pass_file_writer(passwords: list, pass_file: str) -> bool:
    try:
        with open(pass_file, "a") as pfile:
            for password in passwords:
                pfile.write(f"{password}\n")
            pfile.close()
        return True
    except FileNotFoundError:
        logger.error(f"Invalid file path provided for password file {pass_file}")
        sys.exit()  


def hash_file_writer(hashed_passwords: list, hash_file: str) -> bool:
    try:
        with open(hash_file, "a") as hfile:
            for hash in hashed_passwords:
                hfile.write(f"{hash}\n")
            hfile.close()
        return True
    except FileNotFoundError:
        logger.error(f"Invalid file path provided for hash file {hash_file}")
        sys.exit()  


def hash_printer(hashed_passwords: list) -> bool:
    # Easiest way to make sure this function always prints to console if called is to leave output as print statements
    # That also ensures that passwords and hashes don't end up getting stored in the log files
    for hash in hashed_passwords:
        print(hash)
    return True


def pass_printer(passwords: list) -> bool:
    # Easiest way to make sure this function always prints to console if called is to leave output as print statements
    # That also ensures that passwords and hashes don't end up getting stored in the log files
    for password in passwords:
        print(password)
    return True


def main(args: argparse.Namespace) -> bool:
    passwords = []
    hashed_passwords = []
    pword_string = ""
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
        logger.info("Starting password generation process")
        logger.info(f"Generating {number} password(s) of length {length} and strength {strength}")
        pword_string = pword_string_generator(strength)
        passwords = password_generator(length, number, pword_string)
        logger.info(f"{len(passwords)} passwords generated of strength {strength} using the characters: {pword_string}")
    if input_file != None:
        logger.info("Starting password reading process")
        logger.info(f"Reading the password file {input_file} to hash the value(s)")
        passwords = input_file_reader(input_file)
        logger.info(f"A total of {len(passwords)} password(s) were read from {input_file}")
    if hash_algo != None:
        logger.info("Starting password hashing process")
        logger.info(f"Generating {len(passwords)} password hash(es) using {hash_algo}")
        hashed_passwords = hash_generator(passwords, hash_algo)
        logger.info(f"A total of {len(hashed_passwords)} {hash_algo} hash(es) were generated")
    if pass_file != None:
        logger.info(f"Writing {len(passwords)} password(s) to file {pass_file}")
        pass_file_writer(passwords, pass_file)
        logger.info(f"{len(passwords)} password(s) written to file {pass_file}")
    if hash_file != None:
        logger.info(f"Writing {len(hashed_passwords)} {hash_algo} hash(es) to file {hash_file}")
        hash_file_writer(hashed_passwords, hash_file)
        logger.info(f"{len(hashed_passwords)} {hash_algo} hash(es) written to file {hash_file}")
    if print_pass == True or pass_file == None:
        logger.info(f"Printing {len(passwords)} password(s) to console")
        pass_printer(passwords)
    if hash_algo != None and (print_hash == True or hash_file == None):
        logger.info(f"Printing {len(hashed_passwords)} hash(es) to console")
        hash_printer(hashed_passwords)
    return True


if __name__ == "__main__":
    try:
        args = argument_handler()
        logger = logging_factory()
        logger = verbose_logger(args, logger)
        argument_validator(args)
        start_time = datetime.now()
        if main(args):
            logger.info(f"Password and/or hash generation process completed in {datetime.now() - start_time} seconds")
    except KeyboardInterrupt:
        logger.error("Keyboard Interrupt")