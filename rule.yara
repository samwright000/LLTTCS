rule malware
{
// https://www.youtube.com/watch?v=zzpz3VYKzUw
meta:
description = "detecting malware on computer"

strings:

$magic_bytes = {4d 5a} // start of a executable 
$recovery = {52 45 43 4F 56 45 52 59 }
$RECOVERY = { 72 65 63 6F 76 65 72 79 }
$_RECOVERY_ = { 5F 52 45 43 4F 56 45 52 59 5F }
$mp3_extension_hex = { 2E 6D 70 33 } // .mp3
$txtmp3_extension_hex = { 74 78 74 2E 6D 70 33 } //txt.mp3 
$onion_text = ".onion" // link used for money transfer
$onion_hex = { 2E 6F 6E 69 6F 6E }

$advapi32 = "advapi32.dll"
$ntdll = "ntdll.dll"
$kernel32 = "kernel32.dll"

condition:

$magic_bytes at 0 and ($advapi32 and $ntdll and $kernel32) 

and 

( 1 of ($onion_hex, $onion_text, $txtmp3_extension_hex, $mp3_extension_hex, $_RECOVERY_, $RECOVERY, $recovery))

}
