# PassHashGen (PHG)
PassHashGen is a program that generates passwords of specified length, number, and strength[0-3] and provides the option to hash the generated password(s). After password generation and/or hashing is complete PHG will output the hash(es), password(s), or both to the specified text file(s) or console. PHG also has the ability to read a text file of password(s) and convert them to a hash of specified type.

### Purpose
This library is for research and practice purposes. It should be used with hashcat and johntheripper to generate a set number of passwords and hashes of a specific type to test the capabilities of your system without having to use real password dumps.

### Current Hashing Algorithms: 
```md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256```

### Future Goals
1. 1-to-1 parity with the hash types available in hashcat and johntheripper including nested and salted hashing (within reason).
2. More options to customize the passwords generated.
3. Charset mask and dictionary/wordlist building based on password generation with randomization so it is still non-trivial to crack
4. Potentially convert to Cython or utilize Cuda/OpenCL for improved performance
5. Add Multithreading (Waitng for GIL to be removed and stable in the official Python release)
6. Add ability to suppress all console and log output

### Reporting Issues or Requesting Features
If you have a request, find a bug, or would like to help with this endevor, submit an issue or pull request on https://github.com/Laminad/passhashgen

### Known Issues
Fix log file pathing so that logs can write outside of install directory (Getting file permission errors writing to /var/log on Linux)

# Dislcaimer
Please do not use this for production password hashing implementations. It has not been validated or designed for that use case. 
If you do choose to do so, I will not accept liabilty or responsibilty for the outcome.

# Usage and Performance
```
PS C:\Users\lamin> phg -l 25 -s 3 -n 1000000 -m sha3_512 -oh perf_test_hash.txt -op perf_test_pass.txt -v -np -nh
2024-08-13 04:09:37 - INFO - Starting password generation process
2024-08-13 04:09:37 - INFO - Generating 1000000 password(s) of length 25 and strength 3
2024-08-13 04:09:44 - INFO - 1000000 passwords generated of strength 3 using the characters: 1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()
2024-08-13 04:09:44 - INFO - Starting password hashing process
2024-08-13 04:09:44 - INFO - Generating 1000000 password hash(es) using sha3_512
2024-08-13 04:09:45 - INFO - A total of 1000000 sha3_512 hash(es) were generated
2024-08-13 04:09:45 - INFO - Writing 1000000 password(s) to file perf_test_pass.txt
2024-08-13 04:09:46 - INFO - 1000000 password(s) written to file perf_test_pass.txt
2024-08-13 04:09:46 - INFO - Writing 1000000 sha3_512 hash(es) to file perf_test_hash.txt
2024-08-13 04:09:47 - INFO - 1000000 sha3_512 hash(es) written to file perf_test_hash.txt
2024-08-13 04:09:47 - INFO - Password and/or hash generation process completed in 0:00:10.454895 seconds
```

# Installation
This script can be run standalone as long as the dependencies are installed. Pyinstaller can also be used to create binary/executable file to run. I recommend using pyinstaller as it is easier to use binaries/executables in aliases, pyinstaller will validate dependencies, and the resulting executable/binary will be more performant than the .py file.

### Dependencies
Pyinstaller should validate the dependencies, but if you have issues these are the python libraries used. Most are builtin, so they will already be part of a typically python3 installation.
```
python3.5 or newer (python3.12 recommended)
os
sys
random
hashlib
logging
argparse
platform
datetime
pip install os sys random hashlib logging argparse platform datetime
```

### PyInstaller Instructions:
```
pip install -U pyinstaller
git clone https://github.com/Laminad/passhashgen
cd /passhashgen
pyinstaller -F passhashgen.py
```

### Post Installation:
I recommend setting up a shell alias to call the binary/executable after completing the pyinstaller build.

Linux/Unix bash/zsh:
```
[vim|nvim|nano|code] ~/.[bashrc|zshrc|bash_aliases|zsh_aliases]
alias passhashgen="/path/to/passhashgen/dist/passhashgen"
alias phg="/path/to/passhashgen/dist/passhashgen"
source ~/.[bashrc|zshrc|bash_aliases|zsh_aliases]
```

Windows Powershell: 
```
code $profile
Set-Alias -Name passhashgen -Value "C:\path\to\passhashgen\dist\passhashgen.exe"
Set-Alias -Name phg -Value "C:\path\to\passhashgen\dist\passhashgen.exe"
.$profile
```

### Testing the Install and Alias:
Linux/Unix without alias:
```
┌──(laminad㉿DESKTOP)-[~/.passhashgen/dist]
└─$ ./passhashgen -h
usage:

PassHashGen

 [-h] [-l int] [-n int] [-s int] [-m str] [-i str] [-op str] [-oh str] [-np] [-nh] [-v]

A program that generates passwords of the specified length, number, and strength with the ability to hash the password(s) after generating. If an output file(s) is/are provided the hash/passwords/both can be written to the file. If an input file of password(s) is provided it
will convert them to a hash of specified type.

options:
  -h, --help  show this help message and exit
  -l int      Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n int      Flag to set the number of passwords to be generated. If not set default of 1 will be used
  -s int      Flag to set the strength of passwords generated. Set to strong(3) by default [0-3]
  -m str      Flag to set the hashing method to complete on password(s). If not set no hashing will occur. Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256.
  -i str      Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op str     Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh str     Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -np         Flag to enable whether the password(s) print to console. The default is to print the password(s) to console unless textfile provided.
  -nh         Flag to enable whether the hash(es) print to console. The default is to print the hash(es) to console unless textfile provided.
  -v          Flag to enable verbose status messages to console other than hash(es) or password(s). The default is not to print status to console.

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
```

Linux/Unix with alias:
```
┌──(laminad㉿DESKTOP-JUJ33CH)-[/]
└─$ phg -h
usage:

PassHashGen

 [-h] [-l int] [-n int] [-s int] [-m str] [-i str] [-op str] [-oh str] [-np] [-nh] [-v]

A program that generates passwords of the specified length, number, and strength with the ability to hash the password(s) after generating. If an output file(s) is/are provided the hash/passwords/both can be written to the file. If an input file of password(s) is provided it
will convert them to a hash of specified type.

options:
  -h, --help  show this help message and exit
  -l int      Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n int      Flag to set the number of passwords to be generated. If not set default of 1 will be used
  -s int      Flag to set the strength of passwords generated. Set to strong(3) by default [0-3]
  -m str      Flag to set the hashing method to complete on password(s). If not set no hashing will occur. Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256.
  -i str      Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op str     Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh str     Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -np         Flag to enable whether the password(s) print to console. The default is to print the password(s) to console unless textfile provided.
  -nh         Flag to enable whether the hash(es) print to console. The default is to print the hash(es) to console unless textfile provided.
  -v          Flag to enable verbose status messages to console other than hash(es) or password(s). The default is not to print status to console.

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
```


Windows without alias:
```
PS C:\tools\passhashgen\dist> .\passhashgen.exe -h
usage:

PassHashGen

 [-h] [-l int] [-n int] [-s int] [-m str] [-i str] [-op str] [-oh str] [-np] [-nh] [-v]

A program that generates passwords of the specified length, number, and strength with the ability to hash the password(s) after generating. If an output file(s) is/are provided the hash/passwords/both can be written to the file. If an input file of password(s) is provided it
will convert them to a hash of specified type.

options:
  -h, --help  show this help message and exit
  -l int      Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n int      Flag to set the number of passwords to be generated. If not set default of 1 will be used
  -s int      Flag to set the strength of passwords generated. Set to strong(3) by default [0-3]
  -m str      Flag to set the hashing method to complete on password(s). If not set no hashing will occur. Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256.
  -i str      Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op str     Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh str     Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -np         Flag to enable whether the password(s) print to console. The default is to print the password(s) to console unless textfile provided.
  -nh         Flag to enable whether the hash(es) print to console. The default is to print the hash(es) to console unless textfile provided.
  -v          Flag to enable verbose status messages to console other than hash(es) or password(s). The default is not to print status to console.

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
```


Windows with alias:
```
PS C:\Users\lamin> phg -h
usage:

PassHashGen

 [-h] [-l int] [-n int] [-s int] [-m str] [-i str] [-op str] [-oh str] [-np] [-nh] [-v]

A program that generates passwords of the specified length, number, and strength with the ability to hash the password(s) after generating. If an output file(s) is/are provided the hash/passwords/both can be written to the file. If an input file of password(s) is provided it
will convert them to a hash of specified type.

options:
  -h, --help  show this help message and exit
  -l int      Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n int      Flag to set the number of passwords to be generated. If not set default of 1 will be used
  -s int      Flag to set the strength of passwords generated. Set to strong(3) by default [0-3]
  -m str      Flag to set the hashing method to complete on password(s). If not set no hashing will occur. Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256.
  -i str      Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op str     Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh str     Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -np         Flag to enable whether the password(s) print to console. The default is to print the password(s) to console unless textfile provided.
  -nh         Flag to enable whether the hash(es) print to console. The default is to print the hash(es) to console unless textfile provided.
  -v          Flag to enable verbose status messages to console other than hash(es) or password(s). The default is not to print status to console.

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
```