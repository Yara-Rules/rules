rule VirutFileInfector
{
	meta:
    	author = "D00RT <@D00RT_RM>"
    	data = "2017/08/04"

        description = "Virut (unknown version) fileinfector detection"
        reference = "http://reversingminds-blog.logdown.com"

        infected_sample1 = "5755f09d445a5dcab3ea92d978c7c360"
        infected_sample2 = "68e508108ed94c8c391c70ef1d15e0f8"
        infected_sample2 = "2766e8e78ee10264cf1a3f5f4a16ff00"

	strings:
    	$sign = { F9 E8 22 00 00 00 ?? 31 EB 56 }
        $func = { 52 C1 E9 1D 68 31 D4 00 00 58 5A 81 C1 94 01 00 00 80 4D 00 F0 89 6C 24 04 F7 D1 81 6C 24 04 }       
 
    condition:
    	$sign and $func
}
