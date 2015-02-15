rule undocumentedFPUAtEntryPoint {
strings:
    $fpu1 = {D9 D8}
    $fpu2 = {DF DF}
    $fpu3 = {DF D8}
    $fpu4 = {DC D9}
    $fpu5 = {DF DA}
    $fpu6 = {DF CB}
condition:
    (for any of ($fpu*) : ($ at entrypoint)) or $fpu2 in (entrypoint..entrypoint + 10)
}