rule Crowdstrike_Shamoon
{ meta:
description = "Rule to catch Shamoon version A wiper."
strings:
$del1 = "dir \"C:\\Documents and Settings\\\" /s /b /a:-D 2>nul | findstr -i download 2>nul >f1.inf"
$del2 = "dir \"C:\\Documents and Settings\\\" /s /b /a:-D 2>nul | findstr -i document 2>nul >>f1.inf"
$del3 = "dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i download 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i document 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D2>nul | findstr -i picture 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i video 2>nul >>f1.inf dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i music 2>nul >>f1.inf dir \"C:\\Documents and Settings\\\" /s /b /a:-D 2>nul | findstr -i desktop 2>nul >f2.inf"
$del4 = "dir C:\\Users\\ /s /b /a:-D 2>nul | findstr -i desktop 2>nul >>f2.inf dir C:\\Windows\\System32\\Drivers /s /b /a:-D 2>nul >>f2.inf"
$del5 = "dir C:\\Windows\\System32\\Config /s /b /a:-D 2>nul | findstr -v - isystemprofile 2>nul >>f2.inf"
$del6 = "dir f1.inf /s /b 2>nul >>f1.inf dir f2.inf /s /b 2>nul >>f1.inf"
$del7 = { 64 69 72 20 22 43 3A 5C 44 6F 63 75 6D 65 6E 74 73 20 61 6E 64 20 53 65 74 74 69 6E 67 73 5C 22 20 2F 73 20 2F 62 20 2F 61 3A 2D 44 20 32 3E 6E 75 6C}
condition:
($del1 and $del2 and $del3 and $del4 and $del5 and $del6) or $del7 }