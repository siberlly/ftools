rule DFIR_Triage_Test_Marker
{
    meta:
        author = "dfir-browser test fixture"
        description = "Harmless marker rule used by the project test suite"
        reference = "local fixture only"
        severity = "informational"
    strings:
        $marker = "DFIR_TRIAGE_TEST_MARKER" ascii nocase
        $marker_wide = "DFIR_TRIAGE_TEST_MARKER" wide nocase
    condition:
        any of them
}
