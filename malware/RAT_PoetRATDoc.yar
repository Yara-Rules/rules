rule PoetRat_Doc
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch PoetRat Word Document"
        Data = "6th May 2020"
    strings:
        $pythonRegEx = /(\.py$|\.pyc$|\.pyd$|Python)/  // checking for python strings

        // Python file strings in the word documents
        $pythonFile1 = "launcher.py"
        $zipFile = "smile.zip"
        $pythonFile2 = "smile_funs.py"
        $pythonFile3 = "frown.py"
        $pythonFile4 = "backer.py"
        $pythonFile5 = "smile.py"
        $pythonFile6 = "affine.py" 

        // dlls and cmd strings
        $dlls = /\.dll/
        $cmd = "cmd"
        $exe = ".exe"   
    condition:
    all of them        
}
