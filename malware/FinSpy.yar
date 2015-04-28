/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule FinSpy_2
{
    meta:
        description = "FinFisher FinSpy"
	author = "botherder https://github.com/botherder"

    strings:
        $password1 = /\/scomma kbd101\.sys/ wide ascii
        $password2 = /(N)AME,EMAIL CLIENT,EMAIL ADDRESS,SERVER NAME,SERVER TYPE,USERNAME,PASSWORD,PROFILE/ wide ascii
        $password3 = /\/scomma excel2010\.part/ wide ascii
        $password4 = /(A)PPLICATION,PROTOCOL,USERNAME,PASSWORD/ wide ascii
        $password5 = /\/stab MSVCR32\.manifest/ wide ascii
        $password6 = /\/scomma MSN2010\.dll/ wide ascii
        $password7 = /\/scomma Firefox\.base/ wide ascii
        $password8 = /(I)NDEX,URL,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD,FILE,HTTP/ wide ascii
        $password9 = /\/scomma IE7setup\.sys/ wide ascii
        $password10 = /(O)RIGIN URL,ACTION URL,USERNAME FIELD,PASSWORD FIELD,USERNAME,PASSWORD,TIMESTAMP/ wide ascii
        $password11 = /\/scomma office2007\.cab/ wide ascii
        $password12 = /(U)RL,PASSWORD TYPE,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD/ wide ascii
        $password13 = /\/scomma outlook2007\.dll/ wide ascii
        $password14 = /(F)ILENAME,ENCRYPTION,VERSION,CRC,PASSWORD 1,PASSWORD 2,PASSWORD 3,PATH,SIZE,LAST MODIFICATION DATE,ERROR/ wide ascii

        $screenrec1 = /(s)111o00000000\.dat/ wide ascii
        $screenrec2 = /(t)111o00000000\.dat/ wide ascii
        $screenrec3 = /(f)113o00000000\.dat/ wide ascii
        $screenrec4 = /(w)114o00000000\.dat/ wide ascii
        $screenrec5 = /(u)112Q00000000\.dat/ wide ascii
        $screenrec6 = /(v)112Q00000000\.dat/ wide ascii
        $screenrec7 = /(v)112O00000000\.dat/ wide ascii

        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii

        $micrec = /2101[0-9A-F]{8}\.dat/ wide ascii

        $skyperec1 = /\[%19s\] %25s\:    %s/ wide ascii
        $skyperec2 = /Global\\\{A48F1A32\-A340\-11D0\-BC6B\-00A0C903%\.04X\}/ wide
        $skyperec3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii

        $mouserec1 = /(m)sc183Q000\.dat/ wide ascii
        $mouserec2 = /2201[0-9A-F]{8}\.dat/ wide ascii

        $driver = /\\\\\\\\\.\\\\driverw/ wide ascii

        $janedow1 = /(J)ane Dow\'s x32 machine/ wide ascii
        $janedow2 = /(J)ane Dow\'s x64 machine/ wide ascii

        $versions1 = /(f)inspyv2/ nocase
        $versions2 = /(f)inspyv4/ nocase

        $bootkit1 = /(b)ootkit_x32driver/
        $bootkit2 = /(b)ootkit_x64driver/

        $typo1 = /(S)creenShort Recording/ wide

        $mssounddx = /(S)ystem\\CurrentControlSet\\Services\\mssounddx/ wide

    condition:
        8 of ($password*) or any of ($screenrec*) or $micrec or any of ($skyperec*) or any of ($mouserec*) or $driver or any of ($janedow*) or any of ($versions*) or any of ($bootkit*) or $typo1 or $mssounddx
}

rule FinSpy
{
    meta:
        description = "FinFisher FinSpy"
        author = "AlienVault Labs"

    strings:
        $filter1 = "$password14"
        $filter2 = "$screenrec7"
        $filter3 = "$micrec"
        $filter4 = "$skyperec3"
        $filter5 = "$mouserec2"
        $filter6 = "$driver"
        $filter7 = "$janedow2"
        $filter8 = "$bootkit2"

        $password1 = /\/scomma kbd101\.sys/ wide ascii
        $password2 = /(N)AME,EMAIL CLIENT,EMAIL ADDRESS,SERVER NAME,SERVER TYPE,USERNAME,PASSWORD,PROFILE/ wide ascii
        $password3 = /\/scomma excel2010\.part/ wide ascii
        $password4 = /(A)PPLICATION,PROTOCOL,USERNAME,PASSWORD/ wide ascii
        $password5 = /\/stab MSVCR32\.manifest/ wide ascii
        $password6 = /\/scomma MSN2010\.dll/ wide ascii
        $password7 = /\/scomma Firefox\.base/ wide ascii
        $password8 = /(I)NDEX,URL,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD,FILE,HTTP/ wide ascii
        $password9 = /\/scomma IE7setup\.sys/ wide ascii
        $password10 = /(O)RIGIN URL,ACTION URL,USERNAME FIELD,PASSWORD FIELD,USERNAME,PASSWORD,TIMESTAMP/ wide ascii
        $password11 = /\/scomma office2007\.cab/ wide ascii
        $password12 = /(U)RL,PASSWORD TYPE,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD/ wide ascii
        $password13 = /\/scomma outlook2007\.dll/ wide ascii
        $password14 = /(F)ILENAME,ENCRYPTION,VERSION,CRC,PASSWORD 1,PASSWORD 2,PASSWORD 3,PATH,SIZE,LAST MODIFICATION DATE,ERROR/ wide ascii

        $screenrec1 = /(s)111o00000000\.dat/ wide ascii
        $screenrec2 = /(t)111o00000000\.dat/ wide ascii
        $screenrec3 = /(f)113o00000000\.dat/ wide ascii
        $screenrec4 = /(w)114o00000000\.dat/ wide ascii
        $screenrec5 = /(u)112Q00000000\.dat/ wide ascii
        $screenrec6 = /(v)112Q00000000\.dat/ wide ascii
        $screenrec7 = /(v)112O00000000\.dat/ wide ascii

        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii

        $micrec = /2101[0-9A-F]{8}\.dat/ wide ascii

        $skyperec1 = /\[%19s\] %25s\:    %s/ wide ascii
        $skyperec2 = /Global\\\{A48F1A32\-A340\-11D0\-BC6B\-00A0C903%\.04X\}/ wide
        //$skyperec3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii

        //$mouserec1 = /(m)sc183Q000\.dat/ wide ascii
        //$mouserec2 = /2201[0-9A-F]{8}\.dat/ wide ascii

        $driver = /\\\\\\\\\.\\\\driverw/ wide ascii

        $janedow1 = /(J)ane Dow\'s x32 machine/ wide ascii
        $janedow2 = /(J)ane Dow\'s x64 machine/ wide ascii

        //$versions1 = /(f)inspyv2/ nocase
        //$versions2 = /(f)inspyv4/ nocase

        $bootkit1 = /(b)ootkit_x32driver/
        $bootkit2 = /(b)ootkit_x64driver/

        $typo1 = /(S)creenShort Recording/ wide

        $mssounddx = /(S)ystem\\CurrentControlSet\\Services\\mssounddx/ wide

    condition:
        (8 of ($password*) or any of ($screenrec*) or $micrec or any of ($skyperec*) or $driver or any of ($janedow*) or any of ($bootkit*) or $typo1 or $mssounddx) and not any of ($filter*)
}

