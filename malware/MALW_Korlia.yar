/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule korlia
{ 
meta:
author = "Nick Hoffman" 
company = "Morphick"
reference = "http://www.morphick.com/resources/lab-blog/curious-korlia"
information = "korlia malware found in apt dump" 

//case a
//b2 1f mov dl, 0x1f ; mov key (wildcard) 
// ----------------- 
//8A 86 98 40 00 71 mov al, byte ptr url[esi]
//BF 98 40 00 71 mov edi, offset url 
//32 C2 xor al, dl 
//83 C9 FF or ecx, 0FFFFFFFFh 
//88 86 98 40 00 71 mov byte ptr url[esi], al 
//33 C0 xor eax, eax 
//46 inc esi 
//F2 AE repne scasb 
//F7 D1 not ecx 
//49 dec ecx 
//3B F1 cmp esi, ecx 
//72 DE jb short loc_71001DE0

//case b (variant of loop a) 
//8A 8A 28 50 40 00 mov cl, byte_405028[edx] 
//BF 28 50 40 00 mov edi, offset byte_405028 
//32 CB xor cl, bl 
//33 C0 xor eax, eax 
//88 8A 28 50 40 00 mov byte_405028[edx], cl
//83 C9 FF or ecx, 0FFFFFFFFh 
//42 inc edx 
//F2 AE repne scasb 
//F7 D1 not ecx 
//49 dec ecx 
//3B D1 cmp edx, ecx 
//72 DE jb short loc_4047F2 

//case c (not a variant of the above loop) 
//8A 0C 28 mov cl, [eax+ebp] 
//80 F1 28 xor cl, 28h 
//88 0C 28 mov [eax+ebp], cl 
//8B 4C 24 14 mov ecx, [esp+0D78h+var_D64]
//40 inc eax 
//3B C1 cmp eax, ecx 
//7C EE jl short loc_404F1C 

strings:
$a = {b2 ?? 8A 86 98 40 00 71 BF 98 40 00 71 32 c2 83 C9 FF 88 86 98 40 00 71 33 C0 46 F2 AE F7 D1 49 3B F1} 
$b = {B3 ?? ?? ?? 8A 8A 28 50 40 00 BF 28 50 40 00 32 CB 33 C0 88 8A 28 50 40 00 83 C9 FF 42 F2 AE F7 D1 49 3B D1} 
$c = {8A 0C 28 80 F1 ?? 88 0C 28 8B 4C 24 14 40 3B C1} 
$d = {00 62 69 73 6F 6E 61 6C 00} //config marker "\x00bisonal\x00"
condition:
any of them 
}
