[![Build Status](https://travis-ci.org/Neo23x0/Loki.svg?branch=master)](https://travis-ci.org/Neo23x0/Loki)

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
4. C2 Back Connect Check   
   Compares process connection endpoints with C2 IOCs (new since version v.10)

Additional Checks:

1. Regin filesystem check (via --reginfs)
2. Process anomaly check (based on [Sysforensics](http://goo.gl/P99QZQ))
3. SWF decompressed scan (new since version v0.8)
4. SAM dump check
5. DoublePulsar check - tries to detect DoublePulsar backdoor on port 445/tcp and 3389/tcp
6. [PE-Sieve](https://hshrzd.wordpress.com/pe-sieve/) process check

The Windows binary is compiled with PyInstaller 2.1 and should run as x86 application on both x86 and x64 based systems.

## Download

Download the latest version of LOKI from the [releases](https://github.com/Neo23x0/Loki/releases) section.

## How-To Run LOKI and Analyse the Reports

### Run

  - Download the latest LOKI version from the [releases](https://github.com/Neo23x0/Loki/releases) section
  - Run it once to retrieve the latest signature base repository
  - Provide the folder to a target system that should be scanned: removable media, network share, folder on target system
  - Right-click on loki.exe and select "Run as Administrator" or open a command line "cmd.exe" as Administrator and run it from there (you can also run LOKI without administrative privileges but some checks will be disabled and relevant objects on disk will not be accessible)

### Reports

  - The resulting report will show a GREEN, YELLOW or RED result line.
  - Please analyse the findings yourself by:
    1. uploading non-confidential samples to [Virustotal.com](https://www.virustotal.com)
    2. Search the web for the filename
    3. Search the web for keywords from the rule name (e.g. EQUATIONGroupMalware_1 > search for "Equation Group")
    4. Search the web for the MD5 hash of the sample
    5. Search in my [customer APT search engine](https://cse.google.com/cse/publicurl?cx=003248445720253387346:turlh5vi4xc) for file names or identifiers
  - Please report back false positives via the [Issues](https://github.com/Neo23x0/Loki/issues) section (mention the false positive indicator like a hash and/or filename and the rule name that triggered)

## Update

Since version 0.21.0 LOKI includes a separate updater tool named `loki-upgrader.exe` or `loki-upgrader.py`.

```
usage: loki-upgrader.py [-h] [-l log-file] [--sigsonly] [--progonly] [--nolog]
                        [--debug]

Loki - Upgrader

optional arguments:
  -h, --help   show this help message and exit
  -l log-file  Log file
  --sigsonly   Update the signatures only
  --progonly   Update the program files only
  --nolog      Don't write a local log file
  --debug      Debug output
```

It allows to update the compiled loki.exe for Windows and the signature-base sources.

When running `loki.exe --update` it will create an new upgrader process and exits LOKI in order to replace the `loki.exe` with the newer one, which would be locked otherwise.

## Usage

```
usage: loki.exe [-h] [-p path] [-s kilobyte] [-l log-file] [-r remote-loghost]
                [-a alert-level] [-w warning-level] [-n notice-level]
                [--printAll] [--allreasons] [--noprocscan] [--nofilescan]
                [--scriptanalysis] [--rootkit] [--noindicator] [--reginfs]
                [--dontwait] [--intense] [--csv] [--onlyrelevant] [--nolog]
                [--update] [--debug]

Loki - Simple IOC Scanner

optional arguments:
  -h, --help         show this help message and exit
  -p path            Path to scan
  -s kilobyte        Maximum file size to check in KB (default 5000 KB)
  -l log-file        Log file
  -r remote-loghost  Remote syslog system
  -a alert-level     Alert score
  -w warning-level   Warning score
  -n notice-level    Notice score
  --printAll         Print all files that are scanned
  --allreasons       Print all reasons that caused the score
  --noprocscan       Skip the process scan
  --nofilescan       Skip the file scan
  --scriptanalysis   Activate script analysis (beta)
  --rootkit          Skip the rootkit check
  --noindicator      Do not show a progress indicator
  --reginfs          Do check for Regin virtual file system
  --dontwait         Do not wait on exit
  --intense          Intense scan mode (also scan unknown file types and all
                     extensions)
  --csv              Write CSV log format to STDOUT (machine processing)
  --onlyrelevant     Only print warnings or alerts
  --nolog            Don't write a local log file
  --update           Update the signatures from the "signature-base" sub
                     repository
  --debug            Debug output
```

## Build LOKI

No requirements if you use the pre-compiled executables in the `release` section of this repo.

If you want to build LOKI yourself:

### Linux or OS X

- [yara](https://github.com/VirusTotal/yara/) : just use the latest release source code, compile and install it (or install it via pip install yara-python)
- Some Python packages: pip install yara-python psutil netaddr pylzma colorama

### Windows

- [yara](https://github.com/VirusTotal/yara/) : It's recommended to use the most recent version of the compiled packages for Windows (e.g. yara-python-3.5.0.0.win32-py2.7.exe - Download it from here: https://github.com/VirusTotal/yara/releases
- [pywin32](http://sourceforge.net/projects/pywin32/) : path conversions (PyInstaller [issue](https://github.com/pyinstaller/pyinstaller/issues/1282); Windows only)
- Microsoft Visual C++ 2010 Redistributable Package (https://www.microsoft.com/en-US/download/details.aspx?id=5555)
- Microsoft Visual C++ Compiler for Python 2.7 (https://www.microsoft.com/en-us/download/details.aspx?id=44266): for pylzma

```
c:\Python27[-x64]\python.exe -m pip install --upgrade pip
pip.exe install psutil netaddr wmi colorama pylzma pycrypto yara-python pywin32 rfc5424-logging-handler setuptools==19.2 pyinstaller==2.1
```

## Package LOKI with a Private Rule Set

LOKI can be packaged with a custom encrypted rule set, which is embedded in the pyinstaller package.
In order to include your own rules place them in a directory named `private-signatures` in the LOKI directory and execute `build.bat`.

```
loki/
├── private-signatures/  <-- YARA rules places in here will by added to loki.exe
├── signature-base/      <-- clear text and still required (retrieved by loki-upgrader.exe)
│   ├── iocs/
│   ├── yara/
```
In order to successfully run the build script, you need to install PyInstaller. We use PyInstaller 2.1 due the problem
that Packages build with PyInstaller 3 don't run on Windows 2003 and XP based systems.
(yes, we need that in incident response - there are even productive systems out there running Windows 2000 or Windows NT)

The easiest way to do install PyInstaller is:
```
pip install pyinstaller==2.1
```

After that, you can just run the build script.
```
build.bat
```

You can verify whether the signature set is valid by calling `loki-package-builder.py` manually.

```
C:\Python27[-x64]\python.exe loki-package-builder.py --ruledir signatures --target rules
```

The usage of this tool is: 

```
﻿usage: loki-package-builder.py [-h] --ruledir RULEDIR --target TARGET

Package builder for Loki

optional arguments:
  -h, --help         show this help message and exit
  --ruledir RULEDIR  directory containing the rules to build into Loki
  --target TARGET    target where to store the compiled ruleset
```

### Requirements for the Threat Intel Receivers

- [OTX Python SDK](https://github.com/AlienVault-Labs/OTX-Python-SDK)
- [pyMISP](https://github.com/CIRCL/PyMISP)

## Signature and IOCs

Since version 0.15 the Yara signatures reside in the sub-repository [signature-base](https://github.com/Neo23x0/signature-base). You can just download the LOKI release ZIP archive and run LOKI once to download the 'signature-base' sub repository with all the signatures. Since version 0.21.0 a separate updater is provided as `loki-upgrader.exe` or `loki-upgrader.py`. LOKI expects the IOCs and signatures of the `signature-base` repo in a subfolder named `signature-base`. 

The IOC files for hashes and filenames are stored in the './signature-base/iocs' folder. All '.yar' files placed in the './signature-base/yara' folder will be initialized together with the rule set that is already included. Use the 'score' value to define the level of the message upon a signature match.

You can add hash, c2 and filename IOCs by adding files to the './signature-base/iocs' subfolder. All hash IOCs and filename IOC files must be in the format used by LOKI (see the default files). The files must have the strings "hash", "filename" or "c2" in their name to get pulled during initialization.

For Hash IOCs (divided by newline; hash type is detected automatically)
```
Hash;Description [Reference]
```

For Filename IOCs (divided by newline)
```
# Description [Reference]
Regex;Score;False Positive Regex
```

You can use the following external variables in the YARA rules that your provide to LOKI:
```
filename - e.g. condition: $s1 and not filename == 'nmap.exe'
filepath - e.g. condition: filepath == 'C:\Windows\cmd.exe'
extension - e.g. condition: uint32(0) == 0x5a4d and extension == ".txt"
filetype - eg. condition: extension == ".txt" and filetype == "EXE"
(see file-type-signatures.cfg in signature-base repo for all detected file types)
md5 - legacy value
```

## User-Defined Scan Excludes

Since version v0.16.2 LOKI supports the definition of user-defined excludes via "excludes.cfg" in the new "./config" folder. Each line represents a regular expression thats gets applied to the full file path during the directory walk. This way you can exclude certain directories regardless of their drive name or file extensions in certain folders and all files and directories that belong to a product that is sensitive to antivirus scanning.

The '''exclude.cfg''' looks like this:

    # Excluded directories
    #
    # - add directories you want to exclude from the scan
    # - double escape back slashes
    # - values are case-insensitive
    # - remember to use back slashes on Windows and slashes on Linux / Unix / OSX
    # - each line contains a regex that matches somewhere in the full path (case insensitive)
    #   e.g.:
    #   Regex: \\System32\\
    #   Matches C:\Windows\System32\cmd.exe
    #
    #   Regex: /var/log/[^/]+\.log
    #   Matches: /var/log/test.log
    #   Not Matches: /var/log/test.gz
    #

    # Useful examples
    \\Ntfrs\\
    \\Ntds\\
    \\EDB[^\.]+\.log
    Sysvol\\Staging\\Nntfrs_cmp
    \\System Volume Information\\DFSR

## PE-Sieve

Since version 0.26 LOKI integrates @hasherezade's great tool [PE-Sieve](https://github.com/hasherezade/pe-sieve) to detect [process anomalies](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/).

The tool is initialized if LOKI finds it in the `./tools` sub folder during startup. 

## Threat Intel Receivers

Since version v0.10 LOKI includes various threat intel receivers using the public APIs of these services to retrieve and store the IOCs in a format that LOKI understands. It is no problem if these indicators overlap with the ones already included. Loki uses a filename regex or hash only once. (no performance impact)

The threat intel receivers have also been moved to the [signature-base](https://github.com/Neo23x0/signature-base) sub repository with version 0.15 and can be found in "./signature-base/threatintel".

Provide your API key via ```-k APIKEY``` or set it in the script header.

### Open Threat Exchange (OTX) Receiver

It's a simple script that downloads your subscribed events/iocs from [Alienvault OTX](https://otx.alienvault.com) and stores them in the correct format in the './iocs' subfolder. The script is located in the "./threatintel" folder and is named "get-otx-iocs.py". (see requirements above)

```
usage: get-otx-iocs.py [-h] [-k APIKEY] [-o dir] [--verifycert] [--debug]

OTX IOC Receiver

optional arguments:
  -h, --help    show this help message and exit
  -k APIKEY     OTX API key
  -o dir        Output directory
  --verifycert  Verify the server certificate
  --debug       Debug output
```

### MISP Receiver

A simple script that downloads your subscribed events/iocs from a custom [MISP](https://github.com/MISP/MISP) instance and stores them in the correct format in the './iocs' subfolder. YARA rules stored in MISP will be written to the './iocs/yara' subfolder and automatically initialized during startup. The script is located in the "./threatintel" folder and is named "get-misp-iocs.py". (see requirements above)

```
usage: get-misp-iocs.py [-h] [-u URL] [-k APIKEY] [-l tframe] [-o dir]
                        [-y yara-dir] [--verifycert] [--debug]

MISP IOC Receiver

optional arguments:
  -h, --help    show this help message and exit
  -u URL        MISP URL
  -k APIKEY     MISP API key
  -l tframe     Time frame (e.g. 2d, 12h - default=30d)
  -o dir        Output directory
  -y yara-dir   YARA rule output directory
  --verifycert  Verify the server certificate
  --debug       Debug output
```

## Screenshots

Loki Scan

![Screen](/screens/lokititle.png)

Command Line Scan Output

![Screen](/screens/lokicmd.png)

Hash based IOCs

![Screen](/screens/lokiconf1.png)

File Name based IOCs

![Screen](/screens/lokiconf2.png)

Generated log file

![Screen](/screens/lokilog1.png)

## Contact

LOKI scanner on our company homepage
[https://www.nextron-systems.com/loki/](https://www.nextron-systems.com/loki/)

Twitter
[@cyb3rOps](https://twitter.com/Cyb3rOps)
[@thor_scanner](https://twitter.com/thor_scanner)

If you are interested in a corporate solution for APT scanning, check out Loki's big brother [THOR](http://www.bsk-consulting.de/apt-scanner-thor/).

## Compile the Scanner

Download PyInstaller [v2.1](https://github.com/pyinstaller/pyinstaller/releases/tag/v2.1), switch to the pyinstaller program directory and execute:

    python ./pyinstaller.py -F C:\path\to\loki.py

This will create a `loki.exe` in the subfolder `./loki/dist`.

### Pro Tip (optional)

To include the msvcr100.dll to improve the target os compatibility change the line in the file `./loki/loki.spec` that contains `a.binaries,` to the following:

    a.binaries + [('msvcr100.dll', 'C:\Windows\System32\msvcr100.dll', 'BINARY')],

## Use LOKI on Mac OS X

- Download Yara sources from [here](https://github.com/VirusTotal/yara/releases)
- Install openssl (brew install openssl, then sudo cp -r /usr/local/Cellar/openssl/1.0.2h_1/include /usr/local)
- ./build.sh
- sudo make install
- Change to folder ```yara-python```
- Run ```python setup.py install```
- Also install the requirements, ```sudo pip install colorama``` gitpython, netaddr, pylzma etc...
- Download and unpack https://github.com/Neo23x0/signature-base into Loki folder
- cd loki folder, sudo python loki.py -p /

## Alternatives

While LOKI is the only open source scanner in our scanner line up and a purely private project, you may also be interested in our new free scanner [SPARK Core](https://www.nextron-systems.com/spark-core/), which isn't open source but pre-compiled for Windows, Linux and macOS. 

![Screen](/screens/scanner-comparison.png)

## Antivirus - False Positives

The compiled scanner may be detected by antivirus engines. This is caused by the fact that the scanner is a compiled python script that implement some file system and process scanning features that are also used in compiled malware code.

If you don't trust the compiled executable, please compile it yourself.

## License

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

### Signature-Base License

![Creative Commons License](https://i.creativecommons.org/l/by-nc/4.0/88x31.png)

Please note that all signatures and IOC files in the `signature-base` repository, except the YARA rules created by 3rd parties, are licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/).
