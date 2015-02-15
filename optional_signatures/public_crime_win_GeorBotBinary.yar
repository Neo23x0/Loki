rule GeorBotBinary
{
strings:
$a = {63 72 ?? 5F 30 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C}

condition:
all of them
}