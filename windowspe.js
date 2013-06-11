/** Constants **/
var RESOURCE_ENTRY_TYPES = [
	RT_UNKNOWN = {value:0,name:'RT_UNKNOWN'}, RT_CURSOR = {value:1,name:'RT_CURSOR'}, 
	RT_BITMAP = {value:2,name:'RT_BITMAP'}, RT_ICON = {value:3,name:'RT_ICON'}, 
	RT_MENU = {value:4,name:'RT_MENU'}, RT_DIALOG = {value:5,name:'RT_DIALOG'}, 
	RT_STRING = {value:6,name:'RT_STRING'}, RT_FONTDIR = {value:7,name:'RT_FONTDIR'},
	RT_FONT = {value:8,name:'RT_FONT'}, RT_ACCELERATOR=  {value:9,name:'RT_ACCELERATOR'},
	RT_RCDATA = {value:10,position:-1,name:'RT_RCDATA'}, RT_MESSAGETABLE = {value:11,name:'RT_MESSAGETABLE'},
	RT_GROUP_CURSOR = {value:12,name:'RT_GROUP_CURSOR'}, RT_UNKNOWN = {value:0,name:'RT_UNKNOWN'}, 
	RT_GROUP_ICON = {value:14,name:'RT_GROUP_ICON'}, RT_UNKNOWN = {value:0,name:'RT_UNKNOWN'}, 
	RT_VERSION = {value:16,name:'RT_VERSION'}, RT_DLGINCLUDE = {value:17,name:'RT_DLGINCLUDE'}, 
	RT_UNKNOWN= {value:0,name:'RT_UNKNOWN'}, RT_PLUGPLAY = {value:19,name:'RT_PLUGPLAY'},
	RT_VXD = {value:20,name:'RT_VXD'}, RT_ANICURSOR = {value:21,name:'RT_ANICURSOR'}, 
	RT_ANIICON = {value:22,name:'RT_ANIICON'}, RT_HTML= {value:23,name:'RT_HTML'}, 
	RT_MANIFEST = {value:24,name:'RT_MANIFEST'}
];
var IMAGE_DOS_SIGNATURE 				= {value:23117, name:'MSDOS'};
var IMAGE_OS2_SIGNATURE 				= {value:17742, name:'OS2'};
var IMAGE_OS2_SIGNATURE_LE 				= {value:17740, name:'OS2 LE'};
var IMAGE_NT_SIGNATURE 					= {value:17744, name:'NT'};
var	IMAGE_FILE_MACHINE_I386				= {value:332, name:'i386'};
var	IMAGE_FILE_MACHINE_IA64				= {value:512, name:'ia64'};
var IMAGE_FILE_MACHINE_AMD64			= {value:34404, name:'amd64'};
var IMAGE_DIRECTORY_ENTRY_EXPORT 		= 0;		// Export Directory
var IMAGE_DIRECTORY_ENTRY_IMPORT 		= 1;		// Import Directory
var IMAGE_DIRECTORY_ENTRY_RESOURCE 		= 2;		// Resource Directory
var IMAGE_DIRECTORY_ENTRY_EXCEPTION 	= 3;		// Exception Directory
var IMAGE_DIRECTORY_ENTRY_SECURITY 		= 4;		// Security Directory
var IMAGE_DIRECTORY_ENTRY_BASERELOC 	= 5;		// Base Relocation Table
var IMAGE_DIRECTORY_ENTRY_DEBUG 		= 6;		// Debug Directory
var IMAGE_DIRECTORY_ENTRY_COPYRIGHT 	= 7;		// Description String
var IMAGE_DIRECTORY_ENTRY_GLOBALPTR 	= 8;		// Machine Value (MIPS GP)
var IMAGE_DIRECTORY_ENTRY_TLS 			= 9;		// TLS Directory
var IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 	= 10;		// Load Configuration Directory
var IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	= 11;
var IMAGE_DIRECTORY_ENTRY_IAT			= 12;
var IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	= 13;
var IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME	= 14;
var IMAGE_DIRECTORY_ENTRY_RESERVED		= 15;
var IMAGE_SIZEOF_SHORT_NAME 			= 8;
var IMAGE_NUMBEROF_DIRECTORY_ENTRIES 	= 16;
var SIZE_OF_NT_SIGNATURE 				= 4;
var WINDOWS_VERSIONS = [
	{Name:'Windows 8', MajorOperatingSystemVersion:6, MinorOperatingSystemVersion:2 },
	{Name:'Windows 7', MajorOperatingSystemVersion:6, MinorOperatingSystemVersion:1 },
	{Name:'Windows Vista', MajorOperatingSystemVersion:6, MinorOperatingSystemVersion:0 },
	{Name:'Windows XP 64-Bit Edition', MajorOperatingSystemVersion:5, MinorOperatingSystemVersion:2 },
	{Name:'Windows XP', MajorOperatingSystemVersion:5, MinorOperatingSystemVersion:1 },
	{Name:'Windows 2000', MajorOperatingSystemVersion:5, MinorOperatingSystemVersion:0 }
];


/** Helper Functions **/
var LOWORD = function(e) { return (e.value & 0x0000ffff); }
var HIGHBIT = function(e) { return (0x80000000 & e) != 0; }
var STRIPHIGHBIT = function(e) { return ((~0x80000000) & e); }
var GETOFFSETBYADDRESS = function(address, winObj) {
	for(var i=0; i < winObj.SectionHeaders.length; i++)
	{
		var VABegin = winObj.SectionHeaders[i].VirtualAddress;
		var VAEnd = winObj.SectionHeaders[i].SizeOfRawData + VABegin;
		if( VABegin <= address && VAEnd > address )
			return address - winObj.SectionHeaders[i].VirtualOffset;
	}
	return 0;	
}
var GETOFFSETBYDIRECTORY = function(directory, winObj) {
	return GETOFFSETBYADDRESS(winObj.OptionalHeader.DataDirectory[directory].VirtualAddress, winObj);
}
var READ = function(size, wef) {
	var buf = new Buffer(size);
	_fs.readSync(wef.FileDescriptor, buf, 0, size, wef.Position);
	wef.Increment(size);
	return buf;
}


/** Objects and Structures **/
var WindowsExeFile = function(fd)
{
	this.name = 'WindowsPEFile';
	this.FileDescriptor = fd;
	this.Position = 0;
}
WindowsExeFile.prototype.BOOL = function() { return READ(4, this).readUInt32LE(0); }
WindowsExeFile.prototype.BOOLEAN = function() { return READ(1, this).readUInt8(0); }
WindowsExeFile.prototype.BYTE = function() { return READ(1, this).readUInt8(0); };
WindowsExeFile.prototype.UCHAR = function() { return READ(1, this).toString('ascii'); }
WindowsExeFile.prototype.USHORT = function() { return READ(2, this).readUInt16LE(0); }
WindowsExeFile.prototype.LONG = function() { return READ(4, this).readInt32LE(0); }
WindowsExeFile.prototype.ULONG = function() { return READ(4, this).readUInt32LE(0); }
WindowsExeFile.prototype.WCHAR =  function() { return READ(2, this).toString('utf8'); }
WindowsExeFile.prototype.DWORD = function() { return READ(4, this).readUInt32LE(0); }
WindowsExeFile.prototype.WORD = function() { return READ(2, this).readUInt16LE(0); }
WindowsExeFile.prototype.Increment = function(e) { return (this.Position = this.Position + e); }
WindowsExeFile.prototype.ResourceDataIconRead = function() {
 	var obj = {};
	obj.biSize 			= this.DWORD();
	obj.biWidth			= this.LONG();
	obj.biHeight		= this.LONG();
	obj.biPlanes		= this.WORD();
	obj.biBitCount		= this.WORD();
	obj.biCompression	= this.DWORD();
	obj.biSizeImage		= this.DWORD();
	obj.biXPelsPerMeter	= this.LONG();
	obj.biYPelsPerMeter	= this.LONG();
	obj.biClrUsed		= this.DWORD();
	obj.biClrImportant	= this.DWORD();
	obj.Position		= this.Position;
	obj.getDataPosition = function() { return this.Position; };
	obj.getDataSize 	= function() { return (this.biSizeImage == 0) ? obj.biWidth*(obj.biHeight/2)*(obj.biBitCount/8) : this.biSizeImage; };
	return obj;
};
WindowsExeFile.prototype.ResourceDataGroupIconRead = function() {
	var obj = {};
	obj.wReserved 			= this.WORD();		// Currently zero 
	obj.wType				= this.WORD();		// 1 for icons 
	obj.wCount				= this.WORD();		// Number of components 
	obj.Entries				= new Array();
	for(var i=0; i < obj.wCount; i++) {
		var sObj = {};
		sObj.bWidth 		= this.BYTE();
		sObj.bHeight 		= this.BYTE();
		sObj.bColorCount 	= this.BYTE();
		sObj.bReserved 		= this.BYTE();
		sObj.wPlanes 		= this.WORD();
		sObj.wBitCount 		= this.WORD();
		sObj.lBytesInRes 	= this.DWORD();
		sObj.wNameOrdinal 	= this.WORD();
		obj.Entries.push(sObj);
	}
	return obj;
}
WindowsExeFile.prototype.ResourceDataRead = function(p) {
	var obj = {}
	obj.parent			= p;
	obj.OffsetToData 	= this.ULONG();
	obj.Size			= this.ULONG();
	obj.CodePage		= this.ULONG();
	obj.Reserved		= this.ULONG();
	obj.PhysicalAddress	= GETOFFSETBYADDRESS(obj.OffsetToData, this);
	try {
		/* Crawl up the chain to get our type and language */
		var index = obj.parent.parent.parent.parent.parent.Name;
		if(index > RESOURCE_ENTRY_TYPES.length) obj.ResourceType = RT_UNKNOWN;
		else obj.ResourceType = RESOURCE_ENTRY_TYPES[index];
		
		var SavePosition = this.Position;
		this.Position = obj.PhysicalAddress;

		switch(obj.ResourceType.value) {
			case RT_ICON.value:
				obj.Icon = this.ResourceDataIconRead();
				break;
			case RT_GROUP_ICON.value:
				obj.GroupIcon = this.ResourceDataGroupIconRead();
				break;
		}
		
		this.Position = SavePosition;
	} catch(e) {
		obj.ResourceType = RT_UNKNOWN;
		obj.ErrorOccured = 'Cannot read resources, an unknown type was encountered.';
	}
	return obj;
}
WindowsExeFile.prototype.ResourceStringRead = function(p) {
	var obj			= {};
	obj.Length 		= this.ULONG();
	obj.NameString	= this.WCHAR();
	return obj;
}
WindowsExeFile.prototype.ResourceEntryRead = function(p) {
	var obj = {};
	obj.parent			= p;
	obj.Name			= this.ULONG();
	obj.OffsetToData	= this.ULONG();

	var SavePosition	= this.Position;
	this.Position 		= this.ResourcePosition + STRIPHIGHBIT(obj.OffsetToData);
	
	if(HIGHBIT(obj.OffsetToData)) obj.Directory = this.ResourceDirectoryRead(obj);
	else obj.Data = this.ResourceDataRead(obj);
	
	this.Position 		= SavePosition;
	
	return obj;
}
WindowsExeFile.prototype.ResourceDirectoryRead = function(p) {
	var obj = {};
	obj.parent					= p;
	obj.Characteristics			= this.ULONG();
	obj.TimeDateStamp 			= new Date(this.ULONG()*1000);
	obj.MajorVersion			= this.USHORT();
	obj.MinorVersion			= this.USHORT();
	obj.NumberOfNamedEntries 	= this.USHORT();
	obj.NumberOfIdEntries		= this.USHORT();
	obj.Entries					= new Array();
	
	var SavePosition			= this.Position;

	for(var i=0; i < obj.NumberOfNamedEntries + obj.NumberOfIdEntries; i++)
		obj.Entries.push( this.ResourceEntryRead(obj) );

	this.Position = SavePosition;
	
	return obj;
}
WindowsExeFile.prototype.SectionHeaderRead = function() {
	var obj = {};
	obj.Name = ''.concat(
		this.UCHAR(), this.UCHAR(), this.UCHAR(), this.UCHAR(),
		this.UCHAR(), this.UCHAR(), this.UCHAR(), this.UCHAR()
	);
	obj.Misc = this.ULONG();
	obj.PhysicalAddress = obj.Misc;
	obj.VirtualSize = obj.Misc;
	obj.VirtualAddress = this.ULONG();
	obj.SizeOfRawData = this.ULONG();
	obj.PointerToRawData = this.ULONG();
	obj.PointerToRelocations = this.ULONG();
	obj.PointerToLinenumbers = this.ULONG();
	obj.NumberOfRelocations = this.USHORT();
	obj.NumberOfLinenumbers = this.USHORT();
	obj.Characteristics = this.ULONG();	
	obj.VirtualOffset = obj.VirtualAddress - obj.PointerToRawData;
	return obj;
}
WindowsExeFile.prototype.SectionHeadersRead = function() {
	var SectionHeaders = new Array();
	for(var i=0; i < this.FileHeader.NumberOfSections; i++)
		SectionHeaders.push( this.SectionHeaderRead() );
	return SectionHeaders;
}
WindowsExeFile.prototype.DataDirectoryRead = function() {
	var obj = {};
	obj.VirtualAddress = this.ULONG();
	obj.Size = this.ULONG();
	return obj;
}
WindowsExeFile.prototype.OptionalHeaderRead = function() {
	var obj = {};
	obj.Magic = this.USHORT();
    obj.MajorLinkerVersion = this.UCHAR();
    obj.MinorLinkerVersion = this.UCHAR();
    obj.SizeOfCode = this.ULONG();
    obj.SizeOfInitializedData = this.ULONG();
    obj.SizeOfUninitializedData = this.ULONG();
    obj.AddressOfEntryPoint = this.ULONG();
    obj.BaseOfCode = this.ULONG();
    obj.BaseOfData = this.ULONG();
    obj.ImageBase = this.ULONG();
    obj.SectionAlignment = this.ULONG();
    obj.FileAlignment = this.ULONG();
    obj.MajorOperatingSystemVersion = this.USHORT();
    obj.MinorOperatingSystemVersion = this.USHORT();
    obj.MajorImageVersion = this.USHORT();
    obj.MinorImageVersion = this.USHORT();
    obj.MajorSubsystemVersion = this.USHORT();
    obj.MinorSubsystemVersion = this.USHORT();
    obj.Reserved1 = this.ULONG();
    obj.SizeOfImage = this.ULONG();
    obj.SizeOfHeaders = this.ULONG();
    obj.CheckSum = this.ULONG();
    obj.Subsystem = this.USHORT();
    obj.DllCharacteristics = this.USHORT();
	obj.SizeOfStackReserve = this.ULONG();
    obj.SizeOfStackCommit = this.ULONG();
    obj.SizeOfHeapReserve = this.ULONG();
    obj.SizeOfHeapCommit = this.ULONG();
    obj.LoaderFlags = this.ULONG();
    obj.NumberOfRvaAndSizes = this.ULONG();
    obj.DataDirectory = new Array();
	
	for(var i=0; i < WINDOWS_VERSIONS.length; i++)
		if(WINDOWS_VERSIONS[i].MajorOperatingSystemVersion == obj.MajorOperatingSystemVersion &&
			WINDOWS_VERSIONS[i].MinorOperatingSystemVersion == obj.MinorOperatingSystemVersion )
			obj.WindowsVersion = WINDOWS_VERSIONS[i];

	for(var i=0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		obj.DataDirectory.push(this.DataDirectoryRead());

	return obj;
}
WindowsExeFile.prototype.FileHeaderRead = function() {
	var obj = {}
	obj.Machine = this.USHORT();
	obj.Machine = (IMAGE_FILE_MACHINE_I386.value == obj.Machine) ? IMAGE_FILE_MACHINE_I386 : 
		( (IMAGE_FILE_MACHINE_IA64.value == obj.Machine) ? IMAGE_FILE_MACHINE_IA64 : IMAGE_FILE_MACHINE_AMD64 );
	obj.NumberOfSections = this.USHORT();
	obj.TimeDateStamp = new Date(this.ULONG()*1000);
	obj.PointerToSymbolTable = this.ULONG();
	obj.NumberOfSymbols = this.ULONG();
	obj.SizeOfOptionalHeader = this.USHORT();
	obj.Characteristics = this.USHORT();
	return obj;
}
WindowsExeFile.prototype.FileTypeRead = function() {
	var ImageFileTypeWord = this.DWORD();
	
	// Determine the type of PE executable
	if(LOWORD(ImageFileTypeWord) == IMAGE_OS2_SIGNATURE.value) return IMAGE_OS2_SIGNATURE;
	else if (LOWORD(ImageFileTypeWord) == IMAGE_OS2_SIGNATURE_LE.value) return IMAGE_OS2_SIGNATURE_LE;
	else if (ImageFileTypeWord == IMAGE_NT_SIGNATURE.value) return IMAGE_NT_SIGNATURE;
	else if (ImageFileTypeWord == IMAGE_DOS_SIGNATURE.value) return IMAGE_DOS_SIGNATURE;
	else return {value:ImageFileTypeWord, name:'UNKNOWN'};
}
WindowsExeFile.prototype.DosHeaderRead = function() {
	var obj = {}
	obj.e_magic = this.USHORT();	// Magic number
	if(obj.e_magic != IMAGE_DOS_SIGNATURE.value) 
		throw new {name:'NotWindowsPEFile', message:'This does not appear to be a valid Windows PE file.'};
	
	obj.e_cblp = this.USHORT();		// Bytes on last page of file
	obj.e_cp = this.USHORT();		// Pages in file
	obj.e_crlc = this.USHORT();		// Relocations
	obj.e_cparhdr = this.USHORT();	// Size of header in paragraphs
	obj.e_minalloc = this.USHORT();	// Minimum extra paragraphs needed
	obj.e_maxalloc = this.USHORT();	// Maximum extra paragraphs needed
	obj.e_ss = this.USHORT();		// Initial (relative) SS value
	obj.e_sp = this.USHORT();		// Initial SP value
	obj.e_csum = this.USHORT();		// Checksum
	obj.e_ip = this.USHORT();		// Initial IP value
	obj.e_cs = this.USHORT();		// Initial (relative) CS value
	obj.e_lfarlc = this.USHORT();	// File address of relocation table
	obj.e_ovno = this.USHORT();		// Overlay number
	obj.e_res = [ this.USHORT(), this.USHORT(), this.USHORT(), this.USHORT() ]; // Reserved words
	obj.e_oemid = this.USHORT();	// OEM identifier (for e_oeminfo)
	obj.e_oeminfo = this.USHORT();	// OEM information; e_oemid specific
	obj.e_res2 = [
				this.USHORT(), this.USHORT(), this.USHORT(), this.USHORT(), this.USHORT(),
				this.USHORT(), this.USHORT(), this.USHORT(), this.USHORT(), this.USHORT()
			];							// Reserved words
	obj.e_lfanew = this.LONG();		// File address of new exe header
	return obj;
}
WindowsExeFile.prototype.WindowsExeRead = function() {
	this.DosHeader 		= this.DosHeaderRead();			// Read the MSDOS 2 Legacy Header then Jump
	this.Position 		= this.DosHeader.e_lfanew;		// Set the position
	this.FileType 		= this.FileTypeRead();			// Read the file type information for NT PE
	this.FileHeader 	= this.FileHeaderRead();		// Read the file headers
	this.OptionalHeader = this.OptionalHeaderRead();	// Read the optional headers
	this.SectionHeaders = this.SectionHeadersRead();	// Read the section headers
	
	this.ResourcePosition = GETOFFSETBYDIRECTORY(IMAGE_DIRECTORY_ENTRY_RESOURCE, this);
	this.Position 		= this.ResourcePosition;
	this.Resources 		= this.ResourceDirectoryRead(this);	// Read resource headers
	delete this.ResourcePosition;	
}