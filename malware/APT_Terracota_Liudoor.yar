
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule liudoor
{
meta:
        author = "RSA FirstWatch"
        date = "2015-07-23"
        description = "Detects Liudoor daemon backdoor"
        hash0 = "78b56bc3edbee3a425c96738760ee406"
        hash1 = "5aa0510f6f1b0e48f0303b9a4bfc641e"
        hash2 = "531d30c8ee27d62e6fbe855299d0e7de"
        hash3 = "2be2ac65fd97ccc97027184f0310f2f3"
        hash4 = "6093505c7f7ec25b1934d3657649ef07"
        type = "Win32 DLL"

strings:
        $string0 = "Succ"
        $string1 = "Fail"
        $string2 = "pass"
        $string3 = "exit"
        $string4 = "svchostdllserver.dll"
        $string5 = "L$,PQR"
        $string6 = "0/0B0H0Q0W0k0"
        $string7 = "QSUVWh"
        $string8 = "Ht Hu["
condition:
        all of them
}
