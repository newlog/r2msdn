R2MSDN  [![Build Status](https://travis-ci.org/newlog/r2msdn.svg?branch=master)](https://travis-ci.org/newlog/r2msdn)
-----

This [radare2](https://www.radare.org/r/) plugin adds the name of the parameters for Windows imports as well as the MSDN URL where you can find the documentation for such imported function in each address where there's a call to such imports.

As of today, radare2 already adds the name of the parameters for Windows imports (although that functionality is broken right now). The `r2msdn` plugin is still useful in the following cases:

  - You want to add the MSDN URL right next to the import call so you can easily access its documentation
  - You want to add up to date parameter names for Windows imports. These names are kept updated given that they are retrieved dynamically through MSDN search engine. So there's no need for a DB storing them.

Usage
-----

[![asciicast](https://asciinema.org/a/116277.png)](https://asciinema.org/a/116277)

This plugin supports a couple of parameters:

* -b/--binary: Path of the binary. This parameter should not be used when the plugin is executed inside an r2 session.
* -t/--type: Type of information to be added to the binary. You can pass one or many of the options. Available options: urls, imports. Pass them without commas.
* -d/--debug: If debug logs should be printed. URLs queried and addresses where comments have been added will be printed. It can be overwhelming for large binaries.

If executed without parameters, only URLs will be added to all Windows import calls.

```bash
$ r2 <binary>
> #!pipe python ./r2msdn.py
```

This shows how to use the script with all parameters inside an r2 session:

```bash
$ r2 <binary>
> #!pipe python ./r2msdn.py -t urls imports -d
```


Authors
------

[newlog](https://twitter.com/newlog_)
