/*
VoidCrypt/Cortizol ransomware
*/


rule VoidCrypt
{
    meta:
        author = "rivitna"
        family = "ransomware.voidcrypt.windows"
        description = "VoidCrypt/Cortizol ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s1 = "C:\\Users\\Legion\\source\\repos\\" ascii
        $s2 = "C:\\Users\\mammad\\" ascii
        $s3 = "MIIBI" ascii
        $s4 = "C:\\ProgramData\\IDk.txt" ascii
        $s5 = "C:\\ProgramData\\pkey" ascii
        $s6 = "C:\\ProgramData\\prvkey" ascii
        $s7 = "RSAKEY.key" ascii
        $s8 = "net stop MSSQL$CONTOSO1" ascii wide
        $s9 = "netsh firewall set opmode mode=disable" ascii wide
        $s10 = "https://api.my-ip.io/ip" ascii
        $s11 = "api.ipify.org" wide
        $s12 = { 44 69 73 6B ( 73 | 53 ) 69 7A 65 3D }
        $s13 = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNMQWERTYUIOPASDFGHJKLZXCVBNM" ascii
        $s14 = "fuckyoufuckyoufuckyoufuckyoufuckyou" ascii
        $s15 = "\x00threaad\x00" ascii

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (5 of ($s*))
        )
}
