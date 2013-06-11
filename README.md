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
* Dll bindings
* Writing (this is execruciating because it requires rebuilding relocation/offset/RVA/VA addresses) executables.

This has only been tested on image files, object files may or may not work. They are fairly similar in format. 
