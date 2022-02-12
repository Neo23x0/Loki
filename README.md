[![Actively Maintained](https://img.shields.io/badge/Maintenance%20Level-Actively%20Maintained-green.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

![Logo](/lokiicon.jpg)
# Loki - Simple IOC and YARA Scanner

Scanner for Simple Indicators of Compromise

Detection is based on four detection methods:

    1. File Name IOC
       Regex match on full file path/name

    2. Yara Rule Check
       Yara signature match on file data and process memory

    3. Hash Check
       Compares known malicious hashes (MD5, SHA1, SHA256) with scanned files
       
    4. C2 Back Connect Check
       Compares process connection endpoints with C2 IOCs (new since version v.10)
       
Additional Checks:

    1. Regin filesystem check (via --reginfs)
    2. Process anomaly check (based on [Sysforensics](http://goo.gl/P99QZQ)
    3. SWF decompressed scan (new since version v0.8)
    4. SAM dump check

The Windows binary is compiled with PyInstaller and should run as x86 application on both x86 and x64 based systems.

## How-To Run LOKI and Analyse the Reports

### Run

  - Download the newest version of LOKI from the [releases](https://github.com/Neo23x0/Loki/releases) section
  - Extract the program package
  - Run loki-upgrader.exe on system with Internet access to retrieve the newest signatures
  - Bring the program folder to a target system that should be scanned: removable media, network share, folder on target system
  - Open a command line "cmd.exe" as Administrator and run it from there (you can also run LOKI without administrative privileges but some checks will be disabled and relevant objects on disk will not be accessible)

### Reports

  - The resulting report will show a GREEN, YELLOW or RED result line.
  - Please analyse the findings yourself by:
    1. uploading non-confidential samples to Virustotal.com
    2. Search the web for the filename
    3. Search the web for keywords from the rule name (e.g. EQUATIONGroupMalware_1 > search for "Equation Group")
    4. Search the web for the MD5 hash of the sample
  - Please report back false positives via the "Issues" section, which is accessible via the right sidebar (mention the false positive indicator like a hash and/or filename and the rule name that triggered)

## Requirements

No requirements if you use the compiled EXE.

If you want to build it yourself:

- [yara](https://github.com/VirusTotal/yara-python/releases) : It's recommended to use the most recent version of the compiled packages for Windows (x86) - Download it from here: https://github.com/VirusTotal/yara-python/releases
- [colorama](https://pypi.python.org/pypi/colorama) : to color it up
- [psutil](https://pypi.python.org/pypi/psutil) : process checks
- [pywin32](http://sourceforge.net/projects/pywin32/) : path conversions (PyInstaller [issue](https://github.com/pyinstaller/pyinstaller/issues/1282); Windows only)

# Usage

    usage: loki.py [-h] [-p path] [-s kilobyte] [-l log-file] [-r remote-loghost]
                   [-t remote-syslog-port] [-a alert-level] [-w warning-level]
                   [-n notice-level] [--allhds] [--alldrives] [--printall]
                   [--allreasons] [--noprocscan] [--nofilescan] [--vulnchecks]
                   [--nolevcheck] [--scriptanalysis] [--rootkit] [--noindicator]
                   [--dontwait] [--intense] [--csv] [--onlyrelevant] [--nolog]
                   [--update] [--debug] [--maxworkingset MAXWORKINGSET]
                   [--syslogtcp] [--logfolder log-folder] [--nopesieve]
                   [--pesieveshellc] [--nolisten]
                   [--excludeprocess EXCLUDEPROCESS] [--force]
    
    Loki - Simple IOC Scanner
    
    optional arguments:
      -h, --help            show this help message and exit
      -p path               Path to scan
      -s kilobyte           Maximum file size to check in KB (default 5000 KB)
      -l log-file           Log file
      -r remote-loghost     Remote syslog system
      -t remote-syslog-port
                            Remote syslog port
      -a alert-level        Alert score
      -w warning-level      Warning score
      -n notice-level       Notice score
      --allhds              Scan all local hard drives (Windows only)
      --alldrives           Scan all drives (including network drives and
                            removable media)
      --printall            Print all files that are scanned
      --allreasons          Print all reasons that caused the score
      --noprocscan          Skip the process scan
      --nofilescan          Skip the file scan
      --vulnchecks          Run the vulnerability checks
      --nolevcheck          Skip the Levenshtein distance check
      --scriptanalysis      Statistical analysis for scripts to detect obfuscated
                            code (beta)
      --rootkit             Skip the rootkit check
      --noindicator         Do not show a progress indicator
      --dontwait            Do not wait on exit
      --intense             Intense scan mode (also scan unknown file types and
                            all extensions)
      --csv                 Write CSV log format to STDOUT (machine processing)
      --onlyrelevant        Only print warnings or alerts
      --nolog               Don't write a local log file
      --update              Update the signatures from the "signature-base" sub
                            repository
      --debug               Debug output
      --maxworkingset MAXWORKINGSET
                            Maximum working set size of processes to scan (in MB,
                            default 100 MB)
      --syslogtcp           Use TCP instead of UDP for syslog logging
      --logfolder log-folder
                            Folder to use for logging when log file is not
                            specified
      --nopesieve           Do not perform pe-sieve scans
      --pesieveshellc       Perform pe-sieve shellcode scan
      --nolisten            Dot not show listening connections
      --excludeprocess EXCLUDEPROCESS
                            Specify an executable name to exclude from scans, can
                            be used multiple times
      --force               Force the scan on a certain folder (even if excluded
                            with hard exclude in LOKI's code


## Signature and IOCs

Since version 0.15 the Yara signatures reside in the sub-repository [signature-base](https://github.com/Neo23x0/signature-base). You will not get the sub-repository by downloading the LOKI as ZIP file. It will be included when you clone the repository. 

The IOC files for hashes and filenames are stored in the './signature-base/iocs' folder. All '.yar' files placed in the './signature-base/yara' folder will be initialized together with the rule set that is already included. Use the 'score' value to define the level of the message upon a signature match. 

You can add hash, c2 and filename IOCs by adding files to the './signature-base/iocs' subfolder. All hash IOCs and filename IOC files must be in the format used by LOKI (see the default files). The files must have the strings "hash", "filename" or "c2" in their name to get pulled during initialization.  

For Hash IOCs (divided by newline; hash type is detected automatically)
```
Hash;Description [Reference]
```

For Filename IOCs (divided by newline)
```
# (optional) Description [Reference]
Filename as Regex[;Score as integer[;False-positive as Regex]]
```

# User-Defined Scan Excludes

Since version v0.16.2 LOKI supports the definition of user-defined excludes via "excludes.cfg" in the new "./config" folder. Each line represents a regular expression that gets applied to the full file path during the directory walk. This way you can exclude certain directories regardless of their drive name, file extensions in certain folders and all files and directories that belong to a product that is sensitive to antivirus scanning. 

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

# Screenshots

Loki Scan

![Screen](/screens/lokiscan2.png)

Regin Matches

![Screen](/screens/lokiscan1.png)

Regin False Positives

![Screen](/screens/lokiscan3.png)

Hash based IOCs

![Screen](/screens/lokiconf1.png)

File Name based IOCs

![Screen](/screens/lokiconf2.png)

Generated log file

![Screen](/screens/lokilog1.png)

# Contact

LOKI scanner on our company homepage
[https://www.nextron-systems.com/loki/](https://www.nextron-systems.com/loki/)

Twitter
[@cyb3rOps](https://twitter.com/Cyb3rOps)
[@thor_scanner](https://twitter.com/thor_scanner)

If you are interested in a corporate solution for APT scanning, check out Loki's big brother [THOR](https://www.nextron-systems.com/thor/).

# Compile the Scanner

Download [PyInstaller](https://github.com/pyinstaller/pyinstaller/releases/), switch to the pyinstaller program directory and execute:

    python ./pyinstaller.py -F C:\path\to\loki.py

This will create a `loki.exe` in the subfolder `./loki/dist`.

## Pro Tip (optional)

To include the msvcr100.dll to improve the target os compatibility change the line in the file `./loki/loki.spec` that contains `a.binaries,` to the following:

    a.binaries + [('msvcr100.dll', 'C:\Windows\System32\msvcr100.dll', 'BINARY')],
    
# Use LOKI on Mac OS X

- Download Yara sources from [here](https://github.com/VirusTotal/yara/releases)
- Change to folder ```yara-python``` 
- Run ```python setup.py install```
- Also install the requirement mentioned above by ```sudo pip install colorama```

# Antivirus - False Positives

The compiled scanner may be detected by antivirus engines. This is caused by the fact that the scanner is a compiled python script that implement some file system and process scanning features that are also used in compiled malware code.

If you don't trust the compiled executable, please compile it yourself.

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
