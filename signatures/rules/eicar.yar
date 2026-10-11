// EICAR test-file detection. The EICAR string is the industry-standard, harmless
// test file that every antivirus is expected to detect. It contains no malicious
// code — it only verifies that detection works. We match the canonical marker
// substring, which is safe to embed.
rule Eicar_Test_File : testfile eicar {
    meta:
        description = "EICAR standard antivirus test file"
        severity    = "high"
        weight      = 0.95
    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $head   = "X5O!P%@AP"
    condition:
        any of them
}
