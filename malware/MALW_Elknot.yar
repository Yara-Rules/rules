/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule elknot_xor : malware 
{
meta:
    author = "liuya@360.cn"
    date = "2016-04-25"
    description = "elknot/Billgates variants with XOR like C2 encryption scheme"
    reference = "http://liuya0904.blogspot.tw/2016/04/new-elknotbillgates-variant-with-xor.html"
    sample = "474429d9da170e733213940acc9a2b1c, 2579aa65a28c32778790ec1c673abc49"

strings:
   //md5=474429d9da170e733213940acc9a2b1c
   /*
   seg000:08130801 68 00 09 13 08                          push    offset dword_8130900
    seg000:08130806 83 3D 30 17 13 08 02                    cmp     ds:dword_8131730, 2
    seg000:0813080D 75 07                                   jnz     short loc_8130816
    seg000:0813080F 81 04 24 00 01 00 00                    add     dword ptr [esp], 100h
    seg000:08130816                         loc_8130816:                           
    seg000:08130816 50                                      push    eax
    seg000:08130817 E8 15 00 00 00                          call    sub_8130831
    seg000:0813081C E9 C8 F6 F5 FF                          jmp     near ptr 808FEE9h
   */
    $decrypt_c2_func_1 = {08 83 [5] 02 75 07 81 04 24 00 01 00 00 50 e8 [4] e9}

    // md5=2579aa65a28c32778790ec1c673abc49
    /*
    .rodata:08104D20 E8 00 00 00 00                          call    $+5
    .rodata:08104D25 87 1C 24                                xchg    ebx, [esp+4+var_4] ;
    .rodata:08104D28 83 EB 05                                sub     ebx, 5
    .rodata:08104D2B 8D 83 00 FD FF FF                       lea     eax, [ebx-300h]
    .rodata:08104D31 83 BB 10 CA 02 00 02                    cmp     dword ptr [ebx+2CA10h], 2
    .rodata:08104D38 75 05                                   jnz     short loc_8104D3F
    .rodata:08104D3A 05 00 01 00 00                          add     eax, 100h
    .rodata:08104D3F                         loc_8104D3F:                           
    .rodata:08104D3F 50                                      push    eax
    .rodata:08104D40 FF 74 24 10                             push    [esp+8+strsVector]
*/
$decrypt_c2_func_2 = {e8 00 00 00 00 87 [2] 83 eb 05 8d 83 [4] 83 bb [4] 02 75 05}

condition:
    1 of ($decrypt_c2_func_*)
}
