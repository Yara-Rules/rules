rule PoetRat
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch PoetRat Word Document"
        Data = "6th May 2020"
    strings:
        $pythonRegEx = /(\.py$|\.pyc$|\.pyd$|Python)/  // checking for python strings
        $dlls = /\.dll/
        $cmd = "cmd"
        $exe = ".exe"
        $macro1 = "document_open"
        $pipe_out = "Abibliophobia23"
        $shot = "shot_{0}_{1}.png"
    condition:
    any of them        
}