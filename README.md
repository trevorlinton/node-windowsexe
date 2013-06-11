Reads in Microsoft Windows Portable Executable formats (.exe). 

Supports MSDOS, OS/2 and Windows 3.1 to Windows 8.

Currently supports reading
* MSDOS Header
* Portable Executable File Header
* File Type Header
* Optional Header
* Resources
* Data directories

While resources will be read in, it only supports loading icon files. Other types of resources are not supported.
However offsets to the file where the resource data exists is given, the specification for that resource type
would need to be built.

What could be great to add?...
* Export/Import tables
* Relocation tables
* Additional resource type support (cursor, group info, manifests, copyright, security certificates, etc).
* Dll bindings
* Writing (this is execruciating because it requires rebuilding relocation/offset/RVA/VA addresses) executables.
* Assembly/CLR runtime information.

This has only been tested on image files, object files may or may not work. They are fairly similar in format.

Example:
```javascript
fs = require('fs');

fd = fs.openSync('myexecutable.exe','r');
winObj = new WindowsExeFile(fd);
winObj.WindowsExeRead();
```

Various methods read (sometimes recursively) data from the winObj.Position. You can modify the position to anywhere
you want in the file then issue a read for any of the support structures, however 99% of use cases will be executing 
winObj.WindowsExeRead() (e.g., the entire windows file). 

I really only programmed this so I could extract and re-write icon files, so there probably will not be continued
development. Email me if you want access to the repo to continue working on it.
