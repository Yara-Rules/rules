rule MALW_FakePyPI
{
meta:
	description = "Identifies fake PyPI Packages."
	author = "@bartblaze"
	reference = "http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/"
	date = "2017-09"
	tlp = "white"

strings:	
	$ = "# Welcome Here! :)"
	$ = "# just toy, no harm :)"
	$ = "[0x76,0x21,0xfe,0xcc,0xee]"

condition:
	all of them
}
