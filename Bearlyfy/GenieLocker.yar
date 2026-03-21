/*
GenieLocker ransomware
*/


rule GenieLocker
{
    meta:
        author = "rivitna"
        family = "ransomware.genielocker.windows"
        description = "GenieLocker ransomware Windows payload"
        severity = 10
        score = 100

    strings:
        $s0 = "GENIELOCK" ascii
        $s1 = " [SKIP] %s (" ascii
        $s2 = "START encrypt ext=%s threads=%d pct=%d%%" ascii
        $s3 = "Watchdog start failed" ascii
        $s4 = "Missing secret argument\n" ascii
        $s5 = "Invalid secret length\n" ascii
        $s6 = "No files to encrypt in %s\n" ascii
        $s7 = "FAIL %s footer: %s" ascii
        $s8 = "[%s] %d file(s), Jobs: %d, Threads/file: %d\n" ascii
        $s9 = "ERROR: libsodium init failed\n" ascii
        $s10 = "Cannot open SCManager (need admin?)\n" ascii
        $s11 = "Stopping services matching: %s\n" ascii
        $s12 = { 20 5B 46 41 49 4C 5D 20 25 73 20 E2 80 94 20 }
        $s13 = { 4E 6F 20 70 61 74 68 20 73 70 65 63 69 66 69 65 64 20 E2
                 80 94 20 77 69 6C 6C 20 65 6E 63 72 79 70 74 20 61 6C 6C
                 20 64 72 69 76 65 73 }
        $s14 = { 3D DE C0 AD DE 0F 85 ?? ?? 00 00 8B [4-6] 3D DE C0 AD DE
                 0F 85 }
        $s15 = { 33 C0 C7 83 [2] 00 00 44 4C 41 56 E9 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (5 of ($s*))
        )
}
