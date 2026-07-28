// Redacted: proprietary ruleset, available under license.
// This file demonstrates the YARA detection mechanism used by the
// extraction pipeline (src/extraction.py:_local_yara). The production
// ruleset is trained on proprietary phishing/malware datasets and is
// not included in this public repository.

rule example_placeholder_rule
{
    meta:
        author = "ImaniIA"
        description = "Placeholder - see README.md in this directory"
    strings:
        $suspicious_marker = "THIS_IS_A_PLACEHOLDER_RULE_NOT_PRODUCTION"
    condition:
        $suspicious_marker
}
