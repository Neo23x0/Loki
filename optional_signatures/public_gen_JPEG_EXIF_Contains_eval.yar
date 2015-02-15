rule JPEG_EXIF_Contains_eval
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect eval function inside JPG EXIF header (http://blog.sucuri.net/2013/07/malware-hidden-inside-jpg-exif-headers.html)"
        method = "Detect JPEG file and EXIF header ($a) and eval function ($b) inside EXIF data"
    strings:
        $a = {FF E1 ?? ?? 45 78 69 66 00}
        $b = /\Weval\s*\(/
    condition:
        uint16be(0x00) == 0xFFD8 and $a and $b in (@a + 0x12 .. @a + 0x02 + uint16be(@a + 0x02) - 0x06)
}