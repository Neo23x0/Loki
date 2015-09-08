
rule Groups_cpassword {
    meta:
        description = "Groups XML contains cpassword value, which is decrypted password - key is in MSDN http://goo.gl/mHrC8P"
        author = "Florian Roth"
        reference = "http://www.grouppolicy.biz/2013/11/why-passwords-in-group-policy-preference-are-very-bad/"
        date = "2015-09-08"
        score = 50
    strings:
        $s1 = / cpassword=\"[^\"]/ ascii
    condition:
        $s1 and filepath contains "SYSVOL" and extension matches /\.xml/
}
