# Introduction
PassHashGen (PHG)

PassHashGen is a program that generates passwords of the specified length, number, and strength[0-3]. PHG also provides the option to hash the generated password(s) and output either the hash(es), password(s), or both to the specified text file(s) or console. PHG also has an option to read a text file of password(s) and convert them to a hash of specified type.

# Purpose
This library is for research and practice purposes with hashcat and johntheripper. It allows you to generate a set number of passwords and hashes of a specific type to test the capabilities of your system without having to use real password dumps.
Current hashing capabilities: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256
The goal is to get as close to 1-to-1 pariarty as possible with the hash types available in hashcat and johntheripper.

# Reporting Issues or Feature Requests
If you have a request, find a bug, or would like to help with this endevor, submit an issue or pull request on https://github.com/Laminad/passhashgen

# Dislcaimer
DISCLAIMER: Please do not use this for production password hashing implementations. It has not been validated for that purpose. If you do choose to do so, I accept no liabilty or responsibilty for the outcome.

# Installation
This script can be run standalone as long as the dependencies are installed. Pyinstaller can also be used to create binary/executable to run.

# PyInstaller Instructions:
```
pip install -U pyinstaller
git clone https://github.com/Laminad/passhashgen
cd /passhashgen
pyinstaller -F passhashgen.py
```

# Post Installation:
I recommend setting up a shell alias to call the binary/executable after completing the build to run the application

Linux bash/zsh:
```
[vim|nvim|nano|code] ~/[.bashrc|.zshrc|.bash_aliases|.zsh_aliases]
alias passhashgen="/path/to/passhashgen/dist/passhashgen.[bin|elf|exe]"
alias phg="/path/to/passhashgen/dist/passhashgen.[bin|elf|exe]"
source ~/.bash_aliases or ~/.zsh_aliases
source ~/.bashrc or ~/.zshrc
```

Windows Powershell: 
```
Set-Alias -Name passhashgen -Value "C:\filepath\to\passhashgen\dist\passhashgen.exe"
Set-Alias -Name phg -Value "C:\filepath\to\passhashgen\dist\passhashgen.exe"
.$profile
```


Testing the install and Alias:
Linux without alias:
```
┌──(laminad㉿DESKTOP-JUJ33CH)-[~/.passhashgen/dist]
└─$ ./passhashgen -h
usage:

PASSHASHGEN

 [-h] [-l LENGTH] [-n NUMBER] [-s STRENGTH] [-m HASH_ALGO] [-i INPUT_FILE] [-op PASS_FILE] [-oh HASH_FILE] [-pp PRINT_PASS] [-ph PRINT_HASH] [-q QUIET]

A program that generates passwords of the specified length, number, and strength. The option to hash the password(s) and output either the hash/passwords/both to the specified text file(s) is available. It is also possible to read a text file of password(s) and convert them to
a hash of specified type.

options:
  -h, --help      show this help message and exit
  -l LENGTH       Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n NUMBER       Flag to set the number of password(s) to be generated. The default is 1 unless set
  -s STRENGTH     Flag to set the strength of password generated. Set to strong(3) by default [0-3]
  -m HASH_ALGO    Flag to set the hashing method to complete on password(s). Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256. If not set no hashing will occur
  -i INPUT_FILE   Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op PASS_FILE   Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh HASH_FILE   Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -pp PRINT_PASS  Flag to enable or disable whether the password(s) print to console. The default is to print the password(s) to console. Not possible to disable if no output file is provided. 1:Enabled 0:Disabled
  -ph PRINT_HASH  Flag to enable or disable whether the hash(es) to console. Not possible to disable if no output files are provided. The default is to print the hashes to console 1:Enabled 0:Disabled
  -q QUIET        Flag to enable or disable whether the status messages print to console other than hash or passwords. The default is to print status to console 1:Enabled 0:Disabled

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
```

Linux with alias:
```
┌──(laminad㉿DESKTOP-JUJ33CH)-[~/.passhashgen/dist]
└─$ phg -h
usage:

PASSHASHGEN

 [-h] [-l LENGTH] [-n NUMBER] [-s STRENGTH] [-m HASH_ALGO] [-i INPUT_FILE] [-op PASS_FILE] [-oh HASH_FILE] [-pp PRINT_PASS] [-ph PRINT_HASH] [-q QUIET]

A program that generates passwords of the specified length, number, and strength. The option to hash the password(s) and output either the hash/passwords/both to the specified text file(s) is available. It is also possible to read a text file of password(s) and convert them to
a hash of specified type.

options:
  -h, --help      show this help message and exit
  -l LENGTH       Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n NUMBER       Flag to set the number of password(s) to be generated. The default is 1 unless set
  -s STRENGTH     Flag to set the strength of password generated. Set to strong(3) by default [0-3]
  -m HASH_ALGO    Flag to set the hashing method to complete on password(s). Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256. If not set no hashing will occur
  -i INPUT_FILE   Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op PASS_FILE   Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh HASH_FILE   Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -pp PRINT_PASS  Flag to enable or disable whether the password(s) print to console. The default is to print the password(s) to console. Not possible to disable if no output file is provided. 1:Enabled 0:Disabled
  -ph PRINT_HASH  Flag to enable or disable whether the hash(es) to console. Not possible to disable if no output files are provided. The default is to print the hashes to console 1:Enabled 0:Disabled
  -q QUIET        Flag to enable or disable whether the status messages print to console other than hash or passwords. The default is to print status to console 1:Enabled 0:Disabled

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
```


Windows without alias:
```
cd "C:\filepath\to\passhashgen\dist\"
passhashgen.exe -h
PS C:\tools\passhashgen\dist> .\passhashgen.exe -h
usage:

PASSHASHGEN

 [-h] [-l LENGTH] [-n NUMBER] [-s STRENGTH] [-m HASH_ALGO] [-i INPUT_FILE] [-op PASS_FILE] [-oh HASH_FILE] [-pp PRINT_PASS] [-ph PRINT_HASH] [-q QUIET]

A program that generates passwords of the specified length, number, and strength. The option to hash the password(s) and output either the hash/passwords/both to the specified text file(s) is available. It is also possible to read a text file of password(s) and convert them to
a hash of specified type.

options:
  -h, --help      show this help message and exit
  -l LENGTH       Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n NUMBER       Flag to set the number of password(s) to be generated. The default is 1 unless set
  -s STRENGTH     Flag to set the strength of password generated. Set to strong(3) by default [0-3]
  -m HASH_ALGO    Flag to set the hashing method to complete on password(s). Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256. If not set no hashing will occur
  -i INPUT_FILE   Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op PASS_FILE   Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh HASH_FILE   Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -pp PRINT_PASS  Flag to enable or disable whether the password(s) print to console. The default is to print the password(s) to console. Not possible to disable if no output file is provided. 1:Enabled 0:Disabled
  -ph PRINT_HASH  Flag to enable or disable whether the hash(es) to console. Not possible to disable if no output files are provided. The default is to print the hashes to console 1:Enabled 0:Disabled
  -q QUIET        Flag to enable or disable whether the status messages print to console other than hash or passwords. The default is to print status to console 1:Enabled 0:Disabled

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
PS C:\tools\passhashgen\dist>
```


Windows with alias:
```
PS C:\> phg -h
usage:

PASSHASHGEN

 [-h] [-l LENGTH] [-n NUMBER] [-s STRENGTH] [-m HASH_ALGO] [-i INPUT_FILE] [-op PASS_FILE] [-oh HASH_FILE] [-pp PRINT_PASS] [-ph PRINT_HASH] [-q QUIET]

A program that generates passwords of the specified length, number, and strength. The option to hash the password(s) and output either the hash/passwords/both to the specified text file(s) is available. It is also possible to read a text file of password(s) and convert them to
a hash of specified type.

options:
  -h, --help      show this help message and exit
  -l LENGTH       Flag to set the length of password(s) to randomly generate. If not set default length of 8 will be used
  -n NUMBER       Flag to set the number of password(s) to be generated. The default is 1 unless set
  -s STRENGTH     Flag to set the strength of password generated. Set to strong(3) by default [0-3]
  -m HASH_ALGO    Flag to set the hashing method to complete on password(s). Available methods: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, and shake_256. If not set no hashing will occur
  -i INPUT_FILE   Flag to set the input file of password(s) to read and convert to hash. Default is not to read a file unless set
  -op PASS_FILE   Flag to set the output textfile to write the password(s) when complete. If not selected they will be output to console
  -oh HASH_FILE   Flag to set the output textfile to write the hash(es) when complete. If not selected they will be output to console
  -pp PRINT_PASS  Flag to enable or disable whether the password(s) print to console. The default is to print the password(s) to console. Not possible to disable if no output file is provided. 1:Enabled 0:Disabled
  -ph PRINT_HASH  Flag to enable or disable whether the hash(es) to console. Not possible to disable if no output files are provided. The default is to print the hashes to console 1:Enabled 0:Disabled
  -q QUIET        Flag to enable or disable whether the status messages print to console other than hash or passwords. The default is to print status to console 1:Enabled 0:Disabled

Look you want something from me and I want something from you. DOD Base 128 Bit Encryption. What do you think?
```