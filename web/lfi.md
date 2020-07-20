# LFI and RFI

Local and remote file inclusions are often found in PHP applications where another source file is included from a **user-defined variable**.
This allows attackers to execute arbitrary code by loading a page that has existing PHP code on it.

* You can detect potential LFI by identifying pages that load PHP snippets from other pages.
* You can exploit LFI by polluting a file with PHP code (potentially a PHP file) and then load it back to the page.
* You can also exploit LFI by attempting to achieve an arbitrary file read on the system.
* Try RFI as well. E.g. fetch an existing file from the local server via the network (e.g. http://localhost) if LFI doesn't work. Of course, I prefer testing for RFI first because I can control the code that will be loaded by the page.
