/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_UserForm_Object
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document"
		reference = "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
		date = "2016-03-05"
		filetype = "Office documents"
		
	strings:
		$a = "UserForm1"
		$b = "TextBox1"
		$c = "Microsoft Forms 2.0"
	
	condition:
	 	all of them
}
