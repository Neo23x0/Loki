![Logo](/lokiicon.jpg)
# Loki - Simple IOC Scanner

Scanner for Simple Indicators of Compromise

Detection is based on four detection methods:

    1. File Name IOC
       Regex match on full file path/name

    2. Yara Rule Check
       Yara signature match on file data and process memory

    3. Hash check
       Compares known malicious hashes (MD5, SHA1, SHA256) with scanned files

The Windows binary is compiled with PyInstaller 2.1 and should run as x86 application on both x86 and x64 based systems.

### Included IOCs

Loki currently includes the following IOCs:

  - Five Eyes QUERTY Malware (GCHQ / NSA and other government agencies)
  - Regin Malware (GCHQ)
  - Skeleton Key Malware (other state-sponsored Malware)

### Requirements

No requirements if you use the compiled EXE. 

If you want to build it yourself:

- [yara](http://goo.gl/PQjmsf) : It's recommended to use the most recent version of the compiled packages for Windows (x86) - Download it from here: http://goo.gl/PQjmsf
- [scandir](https://github.com/benhoyt/scandir) : faster alternative to os.walk()
- [colorama](https://pypi.python.org/pypi/colorama) : to color it up

### Usage

    usage: loki.exe [-h] [-p path] [-s kilobyte] [--printAll] [--noprocscan]
                    [--nofilescan] [--noindicator] [--debug]

    Loki - Simple IOC Scanner

    optional arguments:
      -h, --help     show this help message and exit
      -p path        Path to scan
      -s kilobyte    Maximum file site to check in KB (default 2000 KB)
      --printAll     Print all files that are scanned
      --noprocscan   Skip the process scan
      --nofilescan   Skip the file scan
      --noindicator  Do not show a progress indicator
      --debug        Debug output

### Screenshots

Loki Scan

![Screen](/screens/lokiscan1.png)

Regin Matches

![Screen](/screens/lokiscan2.png)

Regin False Positives

![Screen](/screens/lokiscan3.png)

Hash based IOCs

![Screen](/screens/lokiconf1.png)

File Name based IOCs

![Screen](/screens/lokiconf2.png)

Generated log file

![Screen](/screens/lokilog1.png)

### Contact

Profile on Company Homepage
http://www.bsk-consulting.de/author/froth/

Twitter
@MalwrSignatures

If you are interested in a corporate solution for APT scanning, check out Loki's big brother THOR:
http://www.bsk-consulting.de/apt-scanner-thor/

# Antivirus - False Positives

The compiled scanner may be detected by antivirus engines. This may be caused by the fact that the scanner is a compiled python script that implement some file system and process scanning features that are also used in compiled malware code. 

If you don't trust the compiled executable, please compile it yourself. 

### Compile the Scanner

Download PyInstaller, switch to the pyinstaller program directory and execute:

    python ./pyinstaller.py -F C:\path\to\skeletonkey-scanner.py

This will create a "skeletonkey-scanner.exe" in the subfolder "./skeletonkey-scanner/dist".

### Pro Tip (optional)

To include the msvcr100.dll to improve the target os compatibility change the line in the file "./skeletonkey-scanner/skeletonkey-scanner.spec" that contains `a.bianries,` to the following:

    a.binaries + [('msvcr100.dll', 'C:\Windows\System32\msvcr100.dll', 'BINARY')],

# License

Loki - Simple IOC Scanner
Copyright (c) 2015 Florian Roth

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/)
