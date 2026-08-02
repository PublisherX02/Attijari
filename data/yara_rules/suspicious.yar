rule suspicious_powershell {
    meta:
        description = "Detects PowerShell invocation in documents"
        severity = "high"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "Invoke-Expression" ascii nocase
        $ps3 = "IEX(" ascii nocase
        $ps4 = "-enc " ascii nocase
        $ps5 = "downloadstring" ascii nocase
        $ps6 = "Start-Process" ascii nocase
    condition:
        any of them
}

rule suspicious_vba_macro {
    meta:
        description = "Detects suspicious VBA macro patterns"
        severity = "high"
    strings:
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Auto_Open" ascii nocase
        $auto3 = "Document_Open" ascii nocase
        $auto4 = "Workbook_Open" ascii nocase
        $shell1 = "Shell(" ascii nocase
        $shell2 = "WScript.Shell" ascii nocase
        $shell3 = "CreateObject" ascii nocase
        $shell4 = "Shell#(" ascii nocase
        $download = "XMLHTTP" ascii nocase
        $env = "Environ(" ascii nocase
    condition:
        any of ($auto*) and any of ($shell*, $download, $env)
}

rule suspicious_pdf_javascript {
    meta:
        description = "Detects JavaScript in PDF-like content"
        severity = "high"
    strings:
        $js1 = "/JavaScript" ascii nocase
        $js2 = "/JS " ascii nocase
        $js3 = "/OpenAction" ascii nocase
        $js4 = "/Launch" ascii nocase
        $js5 = "/AA" ascii nocase
        $js6 = "eval(" ascii nocase
    condition:
        2 of them
}

rule suspicious_exe_in_document {
    meta:
        description = "Detects embedded executable patterns"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $pe = "This program cannot be run in DOS mode"
        $elf = { 7F 45 4C 46 }
    condition:
        any of them
}

rule suspicious_encoded_payload {
    meta:
        description = "Detects base64-encoded executable patterns"
        severity = "medium"
    strings:
        $b64_mz = "TVqQAAMAAAA" ascii
        $b64_pk = "UEsDBBQA" ascii
        $b64_elf = "f0VMRg" ascii
    condition:
        any of them
}

rule html_smuggling {
    meta:
        description = "Detects HTML smuggling — JavaScript reconstructs and auto-downloads a binary blob"
        severity = "critical"
    strings:
        $blob = "new Blob(" ascii nocase
        $createobj = "createObjectURL" ascii nocase
        $atob = "atob(" ascii nocase
        $uint8 = "Uint8Array" ascii nocase
        $download1 = ".download" ascii nocase
        $download2 = "saveAs" ascii nocase
        $charcode = "charCodeAt" ascii nocase
        // Base64 PE header embedded in JS string
        $b64_mz_js = "TVqQ" ascii
        $b64_mz_js2 = "TVpQ" ascii
    condition:
        ($atob and ($blob or $createobj) and ($download1 or $download2 or $charcode))
        or ($uint8 and ($blob or $createobj) and ($download1 or $download2))
        or (($b64_mz_js or $b64_mz_js2) and ($atob or $charcode))
}

rule svg_embedded_script {
    meta:
        description = "Detects SVG files with embedded JavaScript (XSS / exfiltration vector)"
        severity = "high"
    strings:
        $svg = "<svg" ascii nocase
        $script = "<script" ascii nocase
        $eval = "eval(" ascii nocase
        $xhr = "XMLHttpRequest" ascii nocase
        $cookie = "document.cookie" ascii nocase
        $location = "document.location" ascii nocase
        $fetch = "fetch(" ascii nocase
    condition:
        $svg and ($script or $eval) and any of ($xhr, $cookie, $location, $fetch)
}

rule polyglot_file {
    meta:
        description = "Detects polyglot files (multiple valid format headers in one file)"
        severity = "critical"
    strings:
        $pdf = "%PDF" ascii
        $zip_local = { 50 4B 03 04 }
        $java_class = { CA FE BA BE }
        $mz = { 4D 5A }
        $elf = { 7F 45 4C 46 }
        $jar_manifest = "META-INF/MANIFEST" ascii
        $ole = { D0 CF 11 E0 }
    condition:
        // PDF + ZIP/JAR
        ($pdf and ($zip_local or $java_class or $jar_manifest))
        // PDF + executable
        or ($pdf at 0 and ($mz or $elf))
        // OLE + executable hidden inside
        or ($ole at 0 and ($mz in (512..filesize) or $elf in (512..filesize)))
        // Any file starting as one format but containing another's magic
        or ($mz at 0 and $pdf)
        or ($java_class and ($pdf or $mz))
}

rule iso_lnk_payload {
    meta:
        description = "Detects ISO/IMG containers with embedded LNK shortcuts or executables"
        severity = "high"
    strings:
        $iso_sig = "CD001" ascii
        $lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $lnk_header = { 4C 00 00 00 }
        $cmd = "cmd.exe" ascii nocase
        $powershell = "powershell" ascii nocase
        $wscript = "wscript" ascii nocase
        $mshta = "mshta" ascii nocase
    condition:
        $iso_sig and ($lnk_clsid or $lnk_header) and any of ($cmd, $powershell, $wscript, $mshta)
}

rule double_extension {
    meta:
        description = "Detects files with suspicious double extensions hiding executables"
        severity = "high"
    strings:
        $ext1 = ".pdf.exe" ascii nocase
        $ext2 = ".pdf.scr" ascii nocase
        $ext3 = ".doc.exe" ascii nocase
        $ext4 = ".jpg.exe" ascii nocase
        $ext5 = ".xlsx.exe" ascii nocase
        $ext6 = ".pdf.bat" ascii nocase
        $ext7 = ".pdf.cmd" ascii nocase
        $ext8 = ".doc.scr" ascii nocase
        // 2026-08-02: real LNK phishing sample used "Facture_Juin_2026.pdf.lnk"
        // -- a shortcut with a PDF-flavored double extension, same disguise
        // technique as the .exe/.scr variants above.
        $ext9 = ".pdf.lnk" ascii nocase
        $ext10 = ".doc.lnk" ascii nocase
        $ext11 = ".xlsx.lnk" ascii nocase
        $ext12 = ".jpg.lnk" ascii nocase
        // Unicode right-to-left override character
        $rtlo = { E2 80 AE }
    condition:
        any of them
}

rule lnk_split_lolbin_reconstruction {
    meta:
        description = "Detects a LOLBin name (mshta/powershell/certutil) rebuilt from short split environment variables via cmd's delayed-expansion flag, then launched with 'start' -- the literal binary name never appears in the file, defeating plain-string signatures. Confirmed technique across multiple real LNK phishing samples, 2026-08-01 evasive-corpus gap-analysis run."
        severity = "critical"
    strings:
        $delayed_exp = "/v:on" ascii nocase
        $set_kw = "set " ascii nocase
        $start_bang = /start\s*""\s*!\w{1,10}!!\w{1,10}!/ nocase
        $double_amp = "&&" ascii
    condition:
        $delayed_exp and $start_bang and #set_kw >= 2 and $double_amp
}

rule lnk_curl_download_execute_chain {
    meta:
        description = "Detects a shortcut/script that downloads a secondary payload with curl straight into %TMP% and immediately executes it -- confirmed technique in a real LNK phishing sample, 2026-08-01 evasive-corpus gap-analysis run."
        severity = "critical"
    strings:
        $curl1 = "curl.exe" ascii nocase
        $curl2 = "curl " ascii nocase
        $o_flag = /-o \"?%TE?MP%/ nocase
    condition:
        ($curl1 or $curl2) and $o_flag
}

rule lnk_autoit_payload_download {
    meta:
        description = "Detects curl downloading an AutoIt3 compiled script (.a3x) alongside its interpreter -- a common loader technique that runs obfuscated malicious logic through a renamed, legitimate AutoIt binary. Confirmed in a real LNK phishing sample (curl'd a.exe + P.a3x, then ran 'a.exe P.a3x'), 2026-08-01 evasive-corpus gap-analysis run."
        severity = "critical"
    strings:
        $curl = "curl" ascii nocase
        $a3x = ".a3x" ascii nocase
    condition:
        $curl and $a3x
}

rule vbs_xmlhttp_execute_backdoor {
    meta:
        description = "Detects a standalone script that beacons via XMLHTTP/WinHttp and dynamically Executes the response body -- a classic fetch-and-execute backdoor. suspicious_vba_macro requires an AutoOpen/Document_Open-style entry point and misses this, since a standalone .vbs/.wsf backdoor just runs top-to-bottom with no macro entry point at all. Confirmed in a real sample, 2026-08-01 evasive-corpus gap-analysis run. Broadened 2026-08-02 after two more real variants were found: one used POST instead of the originally-assumed GET, and another split '.Open'/'.Send' across concatenated string fragments (e.g. '.Open post' as an array element, 'oXMLHTTP.S' + 'end') specifically to defeat the old literal '.Open \"GET\"' + '.Send' requirements -- the mandatory $open/$send strings are now an OR alongside $responsetext, since Execute()-with-concatenation plus an XMLHTTP/WinHttp object is already the specific, rare signal; the exact HTTP-verb/method-call text is exactly what attackers reliably obfuscate."
        severity = "critical"
    strings:
        $xmlhttp = "XMLHTTP" ascii nocase
        $winhttp = "WinHttp" ascii nocase
        $execute = /Execute\s*("")?\s*\+/ nocase
        $open = /\.Open\s*"?\s*(GET|POST)\s*"?/ nocase
        $send = ".Send" ascii nocase
        $responsetext = "responseText" ascii nocase
    condition:
        ($xmlhttp or $winhttp) and $execute and ($open or $send or $responsetext)
}

rule lnk_mshta_remote_url {
    meta:
        description = "Detects an LNK shortcut whose command line launches mshta.exe directly against a remote http(s) URL -- no obfuscation trick needed to flag this one, since mshta legitimately opens local .hta files and essentially never a bare remote URL as its argument. The other lnk_* rules each target a specific obfuscation technique (split-var reconstruction, curl chains, AutoIt, batch write) and miss the simplest case: a plain, unobfuscated 'mshta.exe <url>'. Confirmed in a real sample, 2026-08-02 follow-up gap-analysis."
        severity = "critical"
    strings:
        $mshta = "mshta" ascii nocase
        $url = /https?:\/\// ascii nocase
    condition:
        $mshta and $url
}

rule rundll32_renamed_temp_export {
    meta:
        description = "Detects a command line invoking rundll32.exe against a file sitting in a Temp directory that lacks a .dll extension -- rundll32 requires a real DLL export table, so pointing it at a renamed payload (.dat/.tmp/.bin/etc.) staged in %TEMP% is a LOLBin-abuse pattern with no legitimate use. Confirmed in a real LNK sample (rundll32.exe ...\\Temp\\htpd.dat, bogus), 2026-08-02 follow-up gap-analysis."
        severity = "high"
    strings:
        $rundll32 = "rundll32" ascii nocase
        $temp_dir = /\\Temp\\/ ascii nocase
        $non_dll_export = /\\[A-Za-z0-9_\-\.]+\.(dat|tmp|bin|txt|log|db)\s*,/ ascii nocase
    condition:
        $rundll32 and $temp_dir and $non_dll_export
}

rule rtf_autolink_remote_object {
    meta:
        description = "Detects an RTF document with an auto-updating linked OLE object (\\objautlink\\objupdate) whose data references an external resource via \\hlsrc -- fetches and embeds remote content automatically when the document is opened, a remote-template-injection-style technique distinct from the directly-embedded (\\objemb) exploits rtf_embedded_ole_object/rtf_malformed_header_equation_exploit already cover. Confirmed in a real sample, 2026-08-02 follow-up gap-analysis."
        severity = "high"
    strings:
        $objautlink = "\\objautlink" ascii nocase
        $objupdate = "\\objupdate" ascii nocase
        $hlsrc = "\\hlsrc" ascii nocase
        $objdata = "\\objdata" ascii nocase
    condition:
        $objautlink and $objupdate and ($hlsrc or $objdata)
}

rule rtf_truncated_header_ole_embed {
    meta:
        description = "Detects an RTF document whose header omits the standard '{\\rtf1' version/control sequence entirely (e.g. '{\\rt{...' instead of '{\\rtf1...') while still embedding an OLE object -- RTF's lenient parser renders it regardless, defeating rtf_embedded_ole_object's exact '{\\rtf' check at offset 0. Distinct from rtf_malformed_header_equation_exploit, which targets junk *inside* the rtf1 control word for Equation Editor exploits specifically (requires the literal 'Equation.3' class name); this covers the broader case of a missing header entirely paired with an arbitrary/garbled \\objclass name. Confirmed in a real sample, 2026-08-02 follow-up gap-analysis."
        severity = "critical"
    strings:
        $rtf_trunc = /\{\\rt[^f]/ ascii
        $objemb = "\\objemb" ascii nocase
        $objclass = "\\objclass" ascii nocase
        $objdata = "\\objdata" ascii nocase
    condition:
        $rtf_trunc at 0 and $objemb and $objclass and $objdata
}

rule ps_backtick_obfuscated_member_invoke {
    meta:
        description = "Detects PowerShell using backtick characters inserted inside a quoted method/property name invoked via '::\"...\"' or '.\"...\"' dynamic member access (e.g. '::\"lOAD`WiThPart`iAlN`AmE\"' for LoadWithPartialName), combined with '-f' format-string reconstruction of short quoted literal fragments -- a known Invoke-Obfuscation-style technique with no legitimate use (real code never needs backticks inside a quoted member name). Confirmed in a real heavily-obfuscated AES-decrypting PowerShell loader (Reflection.Assembly load, Rijndael decrypt, gzip-decompress second stage), 2026-08-02 follow-up gap-analysis -- every cmdlet/class/method name in that sample was reconstructed this way specifically to defeat literal-string signatures."
        severity = "critical"
    strings:
        $backtick_member = /[:.]{1,2}"[A-Za-z0-9]+`[A-Za-z0-9`]{2,}"/ ascii wide
        $format_reconstruct = /-f\s*'[^']{0,30}'\s*,\s*'[^']{0,30}'/ ascii wide nocase
    condition:
        $backtick_member and $format_reconstruct
}

rule js_numeric_padding_tail {
    meta:
        description = "Detects a script padded with meaningless 'randNNN = NNN' assignment lines to inflate file size past AV scan-size limits -- a numeric-junk variant of the same evasion idea as the repeated-line padding in script_padding_evasion, except each line has a unique random value so a plain line-uniqueness check doesn't catch it. Confirmed in a real heavily-obfuscated JS sample, 2026-08-01 evasive-corpus gap-analysis run."
        severity = "high"
    strings:
        $pad = /rand\d{5,}\s*=\s*\d{5,}[\r\n]+rand\d{5,}\s*=\s*\d{5,}[\r\n]+rand\d{5,}\s*=\s*\d{5,}/
    condition:
        $pad
}

rule lnk_batch_write_and_execute {
    meta:
        description = "Detects a command that writes a batch file via echo-redirect then immediately launches it -- the malicious command line only ever exists inside the redirected text, not as a directly-invoked one-liner, which defeats signatures looking for e.g. 'curl ... -o ... && start' as adjacent plain text. Confirmed in a real LNK phishing sample, 2026-08-01 evasive-corpus gap-analysis run."
        severity = "critical"
    strings:
        $echo = "echo " ascii nocase
        $bat_redirect = /> ?"?%TEMP%[^\s"]*\.bat/ nocase
        $start = "start" ascii nocase
    condition:
        $echo and $bat_redirect and $start
}

rule encrypted_attachment_password_pattern {
    meta:
        description = "Detects password hints alongside encrypted content indicators"
        severity = "high"
    strings:
        $pw1 = "password" ascii nocase
        $pw2 = "mot de passe" ascii nocase
        $pw3 = "mdp" ascii nocase
        $enc1 = "encrypted" ascii nocase
        $enc2 = "protected" ascii nocase
        $enc3 = "chiffr" ascii nocase
        $zip_header = { 50 4B 03 04 }
    condition:
        any of ($pw*) and (any of ($enc*) or $zip_header)
}

rule rtf_embedded_ole_object {
    meta:
        description = "Detects RTF documents with embedded OLE objects (CVE-2017-11882 style)"
        severity = "high"
    strings:
        $rtf = "{\\rtf" ascii nocase
        $objdata = "\\objdata" ascii nocase
        $objemb = "\\objemb" ascii nocase
        $objclass = "\\objclass" ascii nocase
        $package = "Package" ascii nocase
        $mz_hex = "4d5a" ascii nocase
    condition:
        $rtf at 0 and ($objdata or $objemb) and ($objclass or $package or $mz_hex)
}

rule rtf_malformed_header_equation_exploit {
    meta:
        description = "Detects an RTF Equation Editor exploit (CVE-2017-11882/CVE-2018-0802 style) whose header has junk text injected inside the '{\\rtf1' control word itself (e.g. '{\\rtCASTOR\\ansi...' instead of '{\\rtf1\\ansi...') specifically to defeat literal '{\\rtf' string signatures -- RTF's own lenient parser ignores the unrecognized control word and renders it fine anyway. rtf_embedded_ole_object's exact '{\\rtf' check misses this. Confirmed in a real sample, 2026-08-01 evasive-corpus gap-analysis run."
        severity = "critical"
    strings:
        $rtf_junk_header = /\{\\rt[a-zA-Z]{2,20}\\ansi/ nocase
        $objclass_eq = "Equation.3" ascii
        $objdata = "\\objdata" ascii nocase
    condition:
        $rtf_junk_header and $objclass_eq and $objdata
}

rule steganography_metadata {
    meta:
        description = "Detects steganography tool signatures in image metadata"
        severity = "high"
    strings:
        $steg1 = "SteganoEncoder" ascii nocase
        $steg2 = "steghide" ascii nocase
        $steg3 = "OpenStego" ascii nocase
        $steg4 = "Stegosuite" ascii nocase
        $steg5 = "SilentEye" ascii nocase
        $steg6 = "LSB" ascii
        $payload = "payload" ascii nocase
        $embedded = "embedded" ascii nocase
        $png = { 89 50 4E 47 }
    condition:
        $png at 0 and (
            any of ($steg1, $steg2, $steg3, $steg4, $steg5, $steg6)
            or ($payload and $embedded)
        )
}

rule office_embedded_ole_action {
    meta:
        description = "Detects Office Open XML (PPSX/PPTX/DOCX) with embedded OLE objects and shell commands"
        severity = "high"
    strings:
        $pk = { 50 4B 03 04 }
        $ole_rel = "oleObject" ascii nocase
        $ole_magic = { D0 CF 11 E0 }
        $cmd = "cmd.exe" ascii nocase
        $powershell = "powershell" ascii nocase
        $wscript = "wscript" ascii nocase
        $mshta = "mshta" ascii nocase
    condition:
        $pk at 0 and $ole_rel and ($ole_magic or $cmd or $powershell or $wscript or $mshta)
}
