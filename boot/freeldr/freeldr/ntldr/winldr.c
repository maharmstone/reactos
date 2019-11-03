/*
 * PROJECT:     FreeLoader
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Windows-compatible NT OS Loader.
 * COPYRIGHT:   Copyright 2006-2019 Aleksey Bragin <aleksey@reactos.org>
 */

#include <freeldr.h>
#include <ndk/ldrtypes.h>
#include "winldr.h"
#include "registry.h"

#include <debug.h>
DBG_DEFAULT_CHANNEL(WINDOWS);

// FIXME: Find a better way to retrieve ARC disk information
extern ULONG reactos_disk_count;
extern ARC_DISK_SIGNATURE_EX reactos_arc_disk_info[];

extern ULONG LoaderPagesSpanned;
extern BOOLEAN AcpiPresent;

extern HEADLESS_LOADER_BLOCK LoaderRedirectionInformation;
extern BOOLEAN WinLdrTerminalConnected;
extern void WinLdrSetupEms(IN PCHAR BootOptions);

PLOADER_SYSTEM_BLOCK WinLdrSystemBlock;

#define RT_VERSION 0x10
#define VS_FFI_SIGNATURE 0xfeef04bd

// debug stuff
VOID DumpMemoryAllocMap(VOID);

// Init "phase 0"
VOID
AllocateAndInitLPB(
    IN USHORT VersionToBoot,
    OUT void** OutLoaderBlock,
    OUT PLOADER_PARAMETER_BLOCK1* OutLoaderBlock1,
    OUT PLOADER_PARAMETER_BLOCK2* OutLoaderBlock2,
    OUT PSETUP_LOADER_BLOCK** SetupBlockPtr,
    OUT PLOADER_PARAMETER_EXTENSION1* OutExtension1,
    OUT PLOADER_PARAMETER_EXTENSION2* OutExtension2)
{
    void* LoaderBlock;
    PLOADER_PARAMETER_BLOCK1 LoaderBlock1;
    PLOADER_PARAMETER_BLOCK2 LoaderBlock2;
    PLOADER_PARAMETER_EXTENSION1 Extension1;
    PLOADER_PARAMETER_EXTENSION2 Extension2;

    /* Allocate and zero-init the Loader Parameter Block */
    WinLdrSystemBlock = MmAllocateMemoryWithType(sizeof(LOADER_SYSTEM_BLOCK),
                                                 LoaderSystemBlock);
    if (WinLdrSystemBlock == NULL)
    {
        UiMessageBox("Failed to allocate memory for system block!");
        return;
    }

    RtlZeroMemory(WinLdrSystemBlock, sizeof(LOADER_SYSTEM_BLOCK));

    if (VersionToBoot >= _WIN32_WINNT_WIN7)
    {
        PLOADER_PARAMETER_EXTENSION_WIN7 Extension;

        LoaderBlock = &WinLdrSystemBlock->u1.LoaderBlockWin7;
        LoaderBlock1 = &WinLdrSystemBlock->u1.LoaderBlockWin7.Block1;
        LoaderBlock2 = &WinLdrSystemBlock->u1.LoaderBlockWin7.Block2;
        *SetupBlockPtr = NULL;

        /* Initialize the Loader Block Extension */
        Extension = &WinLdrSystemBlock->u2.ExtensionWin7;
        LoaderBlock2->Extension = (PLOADER_PARAMETER_EXTENSION)Extension;
        Extension->Extension1.Size = sizeof(LOADER_PARAMETER_EXTENSION_WIN7);

        WinLdrSystemBlock->u1.LoaderBlockWin7.OsMajorVersion = (VersionToBoot & 0xFF00) >> 8;
        WinLdrSystemBlock->u1.LoaderBlockWin7.OsMinorVersion = (VersionToBoot & 0xFF);
        WinLdrSystemBlock->u1.LoaderBlockWin7.Size = sizeof(LOADER_PARAMETER_BLOCK_WIN7);

        Extension1 = &Extension->Extension1;
        Extension2 = &Extension->Extension2;
    }
    else
    {
        PLOADER_PARAMETER_EXTENSION_VISTA Extension;

        LoaderBlock = &WinLdrSystemBlock->u1.LoaderBlockVista;
        LoaderBlock1 = &WinLdrSystemBlock->u1.LoaderBlockVista.Block1;
        LoaderBlock2 = &WinLdrSystemBlock->u1.LoaderBlockVista.Block2;
        *SetupBlockPtr = &WinLdrSystemBlock->u1.LoaderBlockVista.SetupLdrBlock;

        /* Initialize the Loader Block Extension */
        Extension = &WinLdrSystemBlock->u2.ExtensionVista;
        LoaderBlock2->Extension = (PLOADER_PARAMETER_EXTENSION)Extension;
        Extension->Extension1.Size = sizeof(LOADER_PARAMETER_EXTENSION_VISTA);
        Extension->MajorVersion = (VersionToBoot & 0xFF00) >> 8;
        Extension->MinorVersion = (VersionToBoot & 0xFF);

        Extension1 = &Extension->Extension1;
        Extension2 = &Extension->Extension2;
    }

    LoaderBlock1->NlsData = &WinLdrSystemBlock->NlsDataBlock;

    /* Init three critical lists, used right away */
    InitializeListHead(&LoaderBlock1->LoadOrderListHead);
    InitializeListHead(&LoaderBlock1->MemoryDescriptorListHead);
    InitializeListHead(&LoaderBlock1->BootDriverListHead);

    *OutLoaderBlock = LoaderBlock;
    *OutLoaderBlock1 = LoaderBlock1;
    *OutLoaderBlock2 = LoaderBlock2;
    *OutExtension1 = Extension1;
    *OutExtension2 = Extension2;
}

// Init "phase 1"
VOID
WinLdrInitializePhase1(PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
                       PLOADER_PARAMETER_BLOCK2 LoaderBlock2,
                       PSETUP_LOADER_BLOCK* SetupBlockPtr,
                       PLOADER_PARAMETER_EXTENSION1 Extension1,
                       PLOADER_PARAMETER_EXTENSION2 Extension2,
                       PCSTR Options,
                       PCSTR SystemRoot,
                       PCSTR BootPath,
                       USHORT VersionToBoot)
{
    /*
     * Examples of correct options and paths:
     * CHAR Options[] = "/DEBUGPORT=COM1 /BAUDRATE=115200";
     * CHAR Options[] = "/NODEBUG";
     * CHAR SystemRoot[] = "\\WINNT\\";
     * CHAR ArcBoot[] = "multi(0)disk(0)rdisk(0)partition(1)";
     */

    PSTR  LoadOptions, NewLoadOptions;
    CHAR  HalPath[] = "\\";
    CHAR  ArcBoot[MAX_PATH+1];
    CHAR  MiscFiles[MAX_PATH+1];
    ULONG i;
    ULONG_PTR PathSeparator;

    /* Construct SystemRoot and ArcBoot from SystemPath */
    PathSeparator = strstr(BootPath, "\\") - BootPath;
    RtlStringCbCopyNA(ArcBoot, sizeof(ArcBoot), BootPath, PathSeparator);

    TRACE("ArcBoot: '%s'\n", ArcBoot);
    TRACE("SystemRoot: '%s'\n", SystemRoot);
    TRACE("Options: '%s'\n", Options);

    /* Fill ARC BootDevice */
    LoaderBlock1->ArcBootDeviceName = WinLdrSystemBlock->ArcBootDeviceName;
    RtlStringCbCopyA(LoaderBlock1->ArcBootDeviceName, sizeof(WinLdrSystemBlock->ArcBootDeviceName), ArcBoot);
    LoaderBlock1->ArcBootDeviceName = PaToVa(LoaderBlock1->ArcBootDeviceName);

//
// IMPROVE!!
// SetupBlock->ArcSetupDeviceName must be the path to the setup **SOURCE**,
// and not the setup boot path. Indeed they may differ!!

    if (SetupBlockPtr && *SetupBlockPtr)
    {
        PSETUP_LOADER_BLOCK SetupBlock = *SetupBlockPtr;

        /* Adjust the ARC path in the setup block - Matches ArcBoot path */
        SetupBlock->ArcSetupDeviceName = WinLdrSystemBlock->ArcBootDeviceName;
        SetupBlock->ArcSetupDeviceName = PaToVa(SetupBlock->ArcSetupDeviceName);

        /* Convert the setup block pointer */
        *SetupBlockPtr = PaToVa(*SetupBlockPtr);
    }

    /* Fill ARC HalDevice, it matches ArcBoot path */
    LoaderBlock1->ArcHalDeviceName = WinLdrSystemBlock->ArcBootDeviceName;
    LoaderBlock1->ArcHalDeviceName = PaToVa(LoaderBlock1->ArcHalDeviceName);

    /* Fill SystemRoot */
    LoaderBlock1->NtBootPathName = WinLdrSystemBlock->NtBootPathName;
    RtlStringCbCopyA(LoaderBlock1->NtBootPathName, sizeof(WinLdrSystemBlock->NtBootPathName), SystemRoot);
    LoaderBlock1->NtBootPathName = PaToVa(LoaderBlock1->NtBootPathName);

    /* Fill NtHalPathName */
    LoaderBlock1->NtHalPathName = WinLdrSystemBlock->NtHalPathName;
    RtlStringCbCopyA(LoaderBlock1->NtHalPathName, sizeof(WinLdrSystemBlock->NtHalPathName), HalPath);
    LoaderBlock1->NtHalPathName = PaToVa(LoaderBlock1->NtHalPathName);

    /* Fill LoadOptions and strip the '/' switch symbol in front of each option */
    NewLoadOptions = LoadOptions = LoaderBlock1->LoadOptions = WinLdrSystemBlock->LoadOptions;
    RtlStringCbCopyA(LoaderBlock1->LoadOptions, sizeof(WinLdrSystemBlock->LoadOptions), Options);

    do
    {
        while (*LoadOptions == '/')
            ++LoadOptions;

        *NewLoadOptions++ = *LoadOptions;
    } while (*LoadOptions++);

    LoaderBlock1->LoadOptions = PaToVa(LoaderBlock1->LoadOptions);

    /* ARC devices */
    LoaderBlock1->ArcDiskInformation = &WinLdrSystemBlock->ArcDiskInformation;
    InitializeListHead(&LoaderBlock1->ArcDiskInformation->DiskSignatureListHead);

    /* Convert ARC disk information from freeldr to a correct format */
    for (i = 0; i < reactos_disk_count; i++)
    {
        PARC_DISK_SIGNATURE_EX ArcDiskSig;

        /* Allocate the ARC structure */
        ArcDiskSig = FrLdrHeapAlloc(sizeof(ARC_DISK_SIGNATURE_EX), 'giSD');

        if (VersionToBoot >= _WIN32_WINNT_WIN7)
        {
            RtlCopyMemory(ArcDiskSig->ArcName, reactos_arc_disk_info[i].ArcName, sizeof(reactos_arc_disk_info[i].ArcName));

            /* Windows 7 uses a slightly different, undocumented, version of ARC_DISK_SIGNATURE - we
             * translate here from the old style to the new one. */
            ArcDiskSig->u.DiskSignatureWin7.Signature = reactos_arc_disk_info[i].u.DiskSignature.Signature;
            ArcDiskSig->u.DiskSignatureWin7.ArcName = PaToVa(ArcDiskSig->ArcName);
            ArcDiskSig->u.DiskSignatureWin7.CheckSum = reactos_arc_disk_info[i].u.DiskSignature.CheckSum;
            ArcDiskSig->u.DiskSignatureWin7.ValidPartitionTable = reactos_arc_disk_info[i].u.DiskSignature.ValidPartitionTable;
            ArcDiskSig->u.DiskSignatureWin7.xInt13 = reactos_arc_disk_info[i].u.DiskSignature.xInt13;
            ArcDiskSig->u.DiskSignatureWin7.IsGpt = reactos_arc_disk_info[i].u.DiskSignature.IsGpt;
            ArcDiskSig->u.DiskSignatureWin7.Reserved = reactos_arc_disk_info[i].u.DiskSignature.Reserved;

            RtlCopyMemory(ArcDiskSig->u.DiskSignatureWin7.GptSignature, reactos_arc_disk_info[i].u.DiskSignature.GptSignature,
                          sizeof(reactos_arc_disk_info[i].u.DiskSignature.GptSignature));

            ArcDiskSig->u.DiskSignatureWin7.unknown = 0; // something to do with VHDs

            /* Insert into the list */
            InsertTailList(&LoaderBlock1->ArcDiskInformation->DiskSignatureListHead,
                           &ArcDiskSig->u.DiskSignatureWin7.ListEntry);
        }
        else
        {
            /* Copy the data over */
            RtlCopyMemory(ArcDiskSig, &reactos_arc_disk_info[i], sizeof(ARC_DISK_SIGNATURE_EX));

            /* Set the ARC Name pointer */
            ArcDiskSig->u.DiskSignature.ArcName = PaToVa(ArcDiskSig->ArcName);

            /* Insert into the list */
            InsertTailList(&LoaderBlock1->ArcDiskInformation->DiskSignatureListHead,
                        &ArcDiskSig->u.DiskSignature.ListEntry);
        }
    }

    /* Convert all lists to Virtual address */

    /* Convert the ArcDisks list to virtual address */
    List_PaToVa(&LoaderBlock1->ArcDiskInformation->DiskSignatureListHead);
    LoaderBlock1->ArcDiskInformation = PaToVa(LoaderBlock1->ArcDiskInformation);

    /* Convert configuration entries to VA */
    ConvertConfigToVA(LoaderBlock1->ConfigurationRoot);
    LoaderBlock1->ConfigurationRoot = PaToVa(LoaderBlock1->ConfigurationRoot);

    /* Convert all DTE into virtual addresses */
    List_PaToVa(&LoaderBlock1->LoadOrderListHead);

    /* This one will be converted right before switching to virtual paging mode */
    //List_PaToVa(&LoaderBlock1->MemoryDescriptorListHead);

    /* Convert list of boot drivers */
    List_PaToVa(&LoaderBlock1->BootDriverListHead);

    /* FIXME! HACK value for docking profile */
    Extension1->Profile.Status = 2;

    /* Check if FreeLdr detected a ACPI table */
    if (AcpiPresent)
    {
        /* Set the pointer to something for compatibility */
        Extension2->AcpiTable = (PVOID)1;
        // FIXME: Extension->AcpiTableSize;
    }

    Extension2->BootViaWinload = 1;

    InitializeListHead(&Extension2->BootApplicationPersistentData);
    List_PaToVa(&Extension2->BootApplicationPersistentData);

    InitializeListHead(&Extension2->AttachedHives);
    List_PaToVa(&Extension2->AttachedHives);

    Extension2->TpmBootEntropyResult.ResultCode = TpmBootEntropyNoTpmFound;
    Extension2->TpmBootEntropyResult.ResultStatus = STATUS_NOT_IMPLEMENTED;

    Extension2->LoaderPerformanceData = PaToVa(&WinLdrSystemBlock->LoaderPerformanceData);

#ifdef _M_IX86
    /* Set headless block pointer */
    if (WinLdrTerminalConnected)
    {
        Extension2->HeadlessLoaderBlock = &WinLdrSystemBlock->HeadlessLoaderBlock;
        RtlCopyMemory(Extension2->HeadlessLoaderBlock,
                      &LoaderRedirectionInformation,
                      sizeof(HEADLESS_LOADER_BLOCK));
        Extension2->HeadlessLoaderBlock = PaToVa(Extension2->HeadlessLoaderBlock);
    }
#endif
    /* Load drivers database */
    RtlStringCbCopyA(MiscFiles, sizeof(MiscFiles), BootPath);
    RtlStringCbCatA(MiscFiles, sizeof(MiscFiles), "AppPatch\\drvmain.sdb");
    Extension2->DrvDBImage = PaToVa(WinLdrLoadModule(MiscFiles,
                                                    &Extension2->DrvDBSize,
                                                    LoaderRegistryData));

    /* Convert the extension block pointer */
    LoaderBlock2->Extension = PaToVa(LoaderBlock2->Extension);

    TRACE("WinLdrInitializePhase1() completed\n");
}

static BOOLEAN
WinLdrLoadDeviceDriver(PLIST_ENTRY LoadOrderListHead,
                       PCSTR BootPath,
                       PUNICODE_STRING FilePath,
                       ULONG Flags,
                       PLDR_DATA_TABLE_ENTRY *DriverDTE)
{
    CHAR FullPath[1024];
    CHAR FullFileName[1024];
    CHAR ArcPath[1024];
    CHAR DriverPath[1024];
    CHAR DllName[1024];
    PCHAR DriverNamePos;
    BOOLEAN Success;
    PVOID DriverBase = NULL;

    // Separate the path to file name and directory path
    RtlStringCbPrintfA(DriverPath, sizeof(DriverPath), "%wZ", FilePath);
    DriverNamePos = strrchr(DriverPath, '\\');
    if (DriverNamePos != NULL)
    {
        // Copy the name
        RtlStringCbCopyA(DllName, sizeof(DllName), DriverNamePos+1);

        // Cut out the name from the path
        *(DriverNamePos+1) = ANSI_NULL;
    }
    else
    {
        // There is no directory in the path
        RtlStringCbCopyA(DllName, sizeof(DllName), DriverPath);
        *DriverPath = ANSI_NULL;
    }

    TRACE("DriverPath: '%s', DllName: '%s', LPB\n", DriverPath, DllName);

    // Check if driver is already loaded
    Success = PeLdrCheckForLoadedDll(LoadOrderListHead, DllName, DriverDTE);
    if (Success)
    {
        // We've got the pointer to its DTE, just return success
        return TRUE;
    }

    // It's not loaded, we have to load it
    RtlStringCbPrintfA(ArcPath, sizeof(ArcPath), "%s%wZ", BootPath, FilePath);
    Success = PeLdrLoadImage(ArcPath, LoaderBootDriver, &DriverBase);
    if (!Success)
        return FALSE;

    // Allocate a DTE for it
    RtlStringCbPrintfA(FullFileName, sizeof(FullFileName), "\\SystemRoot\\%s%s", DriverPath, DllName);

    Success = PeLdrAllocateDataTableEntry(LoadOrderListHead, DllName, FullFileName, DriverBase, DriverDTE);
    if (!Success)
    {
        ERR("PeLdrAllocateDataTableEntry() failed\n");
        return FALSE;
    }

    // Modify any flags, if needed
    (*DriverDTE)->Flags |= Flags;

    // Look for any dependencies it may have, and load them too

    RtlStringCbPrintfA(ArcPath, sizeof(ArcPath), "%s%s", BootPath, DriverPath);
    RtlStringCbPrintfA(FullPath, sizeof(FullPath), "\\SystemRoot\\%s%s", DriverPath);

    Success = PeLdrScanImportDescriptorTable(LoadOrderListHead, FullPath, ArcPath, *DriverDTE);
    if (!Success)
    {
        ERR("PeLdrScanImportDescriptorTable() failed for %s\n", FullPath);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
WinLdrLoadBootDrivers(PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
                      PCSTR BootPath)
{
    PLIST_ENTRY NextBd;
    PBOOT_DRIVER_LIST_ENTRY BootDriver;
    BOOLEAN Success;
    BOOLEAN ret = TRUE;

    // Walk through the boot drivers list
    NextBd = LoaderBlock1->BootDriverListHead.Flink;

    while (NextBd != &LoaderBlock1->BootDriverListHead)
    {
        BootDriver = CONTAINING_RECORD(NextBd, BOOT_DRIVER_LIST_ENTRY, Link);

        TRACE("BootDriver %wZ DTE %08X RegPath: %wZ\n", &BootDriver->FilePath,
            BootDriver->LdrEntry, &BootDriver->RegistryPath);

        // Paths are relative (FIXME: Are they always relative?)

        // Load it
        Success = WinLdrLoadDeviceDriver(&LoaderBlock1->LoadOrderListHead,
                                         BootPath,
                                         &BootDriver->FilePath,
                                         0,
                                         &BootDriver->LdrEntry);

        if (Success)
        {
            // Convert the RegistryPath and DTE addresses to VA since we are not going to use it anymore
            BootDriver->RegistryPath.Buffer = PaToVa(BootDriver->RegistryPath.Buffer);
            BootDriver->FilePath.Buffer = PaToVa(BootDriver->FilePath.Buffer);
            BootDriver->LdrEntry = PaToVa(BootDriver->LdrEntry);
        }
        else
        {
            // Loading failed - cry loudly
            ERR("Can't load boot driver '%wZ'!\n", &BootDriver->FilePath);
            UiMessageBox("Can't load boot driver '%wZ'!", &BootDriver->FilePath);
            ret = FALSE;

            // Remove it from the list and try to continue
            RemoveEntryList(NextBd);
        }

        NextBd = BootDriver->Link.Flink;
    }

    return ret;
}

PVOID
WinLdrLoadModule(PCSTR ModuleName,
                 PULONG Size,
                 TYPE_OF_MEMORY MemoryType)
{
    ULONG FileId;
    PVOID PhysicalBase;
    FILEINFORMATION FileInfo;
    ULONG FileSize;
    ARC_STATUS Status;
    ULONG BytesRead;

    //CHAR ProgressString[256];

    /* Inform user we are loading files */
    //UiDrawBackdrop();
    //RtlStringCbPrintfA(ProgressString, sizeof(ProgressString), "Loading %s...", FileName);
    //UiDrawProgressBarCenter(1, 100, ProgressString);

    TRACE("Loading module %s\n", ModuleName);
    *Size = 0;

    /* Open the image file */
    Status = ArcOpen((PSTR)ModuleName, OpenReadOnly, &FileId);
    if (Status != ESUCCESS)
    {
        /* In case of errors, we just return, without complaining to the user */
        WARN("Error while opening '%s', Status: %u\n", ModuleName, Status);
        return NULL;
    }

    /* Retrieve its size */
    Status = ArcGetFileInformation(FileId, &FileInfo);
    if (Status != ESUCCESS)
    {
        ArcClose(FileId);
        return NULL;
    }
    FileSize = FileInfo.EndingAddress.LowPart;
    *Size = FileSize;

    /* Allocate memory */
    PhysicalBase = MmAllocateMemoryWithType(FileSize, MemoryType);
    if (PhysicalBase == NULL)
    {
        ERR("Could not allocate memory for '%s'\n", ModuleName);
        ArcClose(FileId);
        return NULL;
    }

    /* Load the whole file */
    Status = ArcRead(FileId, PhysicalBase, FileSize, &BytesRead);
    ArcClose(FileId);
    if (Status != ESUCCESS)
    {
        WARN("Error while reading '%s', Status: %u\n", ModuleName, Status);
        return NULL;
    }

    TRACE("Loaded %s at 0x%x with size 0x%x\n", ModuleName, PhysicalBase, FileSize);

    return PhysicalBase;
}

typedef struct _VS_FIXEDFILEINFO {
    ULONG dwSignature;
    ULONG dwStrucVersion;
    ULONG dwFileVersionMS;
    ULONG dwFileVersionLS;
    ULONG dwProductVersionMS;
    ULONG dwProductVersionLS;
    ULONG dwFileFlagsMask;
    ULONG dwFileFlags;
    ULONG dwFileOS;
    ULONG dwFileType;
    ULONG dwFileSubtype;
    ULONG dwFileDateMS;
    ULONG dwFileDateLS;
} VS_FIXEDFILEINFO, *PVS_FIXEDFILEINFO;

typedef struct _VS_VERSION_INFO
{
    USHORT wLength;
    USHORT wValueLength;
    USHORT wType;
    WCHAR szKey[15];
    USHORT Padding1;
    VS_FIXEDFILEINFO Value;
} VS_VERSION_INFO, *PVS_VERSION_INFO;

static USHORT WinLdrParseVersionBlock(PIMAGE_RESOURCE_DIRECTORY_ENTRY DirEntry,
                                      PVOID ImageAddress,
                                      ULONG ImageSize,
                                      PVOID SectionAddress,
                                      ULONG SectionSize)
{
    PIMAGE_RESOURCE_DATA_ENTRY DataEntry;
    PVS_VERSION_INFO Data;

    static const WCHAR Key[] = L"VS_VERSION_INFO";

    if (DirEntry->OffsetToDirectory > SectionSize)
        return 0;

    if (DirEntry->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > SectionSize)
        return 0;

    DataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((char*)SectionAddress + DirEntry->OffsetToDirectory);

    if (DataEntry->OffsetToData + DataEntry->Size > ImageSize)
        return 0;

    if (DataEntry->Size < sizeof(VS_VERSION_INFO))
        return 0;

    Data = (PVS_VERSION_INFO)((char*)ImageAddress + DataEntry->OffsetToData);

    if (Data->wLength > DataEntry->Size)
        return 0;

    if (Data->wValueLength < sizeof(VS_FIXEDFILEINFO))
        return 0;

    if (memcmp(Data->szKey, Key, sizeof(Key)))
        return 0;

    if (Data->Value.dwSignature != VS_FFI_SIGNATURE)
        return 0;

    TRACE("version %08x\n", Data->Value.dwFileVersionMS);

    return (Data->Value.dwFileVersionMS & 0xff0000) >> 8 | (Data->Value.dwFileVersionMS & 0xff);
}

static
USHORT
WinLdrSearchRsrcVersions(PIMAGE_RESOURCE_DIRECTORY_ENTRY DirEntry,
                         PVOID ImageAddress,
                         ULONG ImageSize,
                         PVOID SectionAddress,
                         ULONG SectionSize,
                         BOOLEAN NameDir)
{
    PIMAGE_RESOURCE_DIRECTORY RsrcDir;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY DirEntries;
    ULONG i;

    if (DirEntry->OffsetToDirectory > SectionSize)
        return 0;

    if (DirEntry->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY) > SectionSize)
        return 0;

    RsrcDir = (PIMAGE_RESOURCE_DIRECTORY)((char*)SectionAddress + DirEntry->OffsetToDirectory);

    if (DirEntry->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY) +
        ((RsrcDir->NumberOfNamedEntries + RsrcDir->NumberOfIdEntries) * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) > SectionSize)
        return 0;

    DirEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((char*)SectionAddress +
                                                   DirEntry->OffsetToDirectory +
                                                   sizeof(IMAGE_RESOURCE_DIRECTORY));

    for (i = 0; i < RsrcDir->NumberOfNamedEntries + RsrcDir->NumberOfIdEntries; i++)
    {
        ULONG Version;

        if (NameDir)
            Version = WinLdrSearchRsrcVersions(&DirEntries[i], ImageAddress, ImageSize,
                                               SectionAddress, SectionSize, FALSE);
        else
            Version = WinLdrParseVersionBlock(&DirEntries[i], ImageAddress, ImageSize,
                                              SectionAddress, SectionSize);

        if (Version != 0)
            return Version;
    }

    return 0;
}

static
USHORT
WinLdrFindKernelVersion(PVOID ImageAddress,
                        ULONG ImageSize,
                        PVOID SectionAddress,
                        ULONG SectionSize)
{
    PIMAGE_RESOURCE_DIRECTORY RsrcDir;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY DirEntries;
    ULONG i;

    if (SectionSize < sizeof(IMAGE_RESOURCE_DIRECTORY))
        return 0;

    RsrcDir = SectionAddress;

    if (SectionSize < sizeof(IMAGE_RESOURCE_DIRECTORY) +
        ((RsrcDir->NumberOfNamedEntries + RsrcDir->NumberOfIdEntries) * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)))
        return 0;

    DirEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((char*)SectionAddress + sizeof(IMAGE_RESOURCE_DIRECTORY));

    for (i = 0; i < RsrcDir->NumberOfIdEntries; i++)
    {
        if (DirEntries[RsrcDir->NumberOfNamedEntries + i].Id == RT_VERSION)
        {
            ULONG Version;

            Version = WinLdrSearchRsrcVersions(&DirEntries[RsrcDir->NumberOfNamedEntries + i],
                                               ImageAddress,
                                               ImageSize,
                                               SectionAddress,
                                               SectionSize,
                                               TRUE);

            if (Version != 0)
                return Version;
        }
    }

    return 0;
}

USHORT
WinLdrDetectVersion(PVOID KernelAddress)
{
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeader;
    ULONG i, NumberOfSections;

    NtHeaders = RtlImageNtHeader(KernelAddress);
    if (!NtHeaders)
    {
        ERR("No NT header found in kernel\n");
        UiMessageBox("Error: No NT header found in kernel\n");
        return 0;
    }

    NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
    SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

    /* Look for resource sections in kernel */
    for (i = 0; i < NumberOfSections; i++)
    {
        if (!strcmp((char*)SectionHeader->Name, ".rsrc"))
        {
            USHORT Version;

            Version = WinLdrFindKernelVersion(KernelAddress,
                                              NtHeaders->OptionalHeader.SizeOfImage,
                                              (char*)KernelAddress + SectionHeader->VirtualAddress,
                                              SectionHeader->Misc.VirtualSize);

            if (Version != 0)
                return Version;
        }

        SectionHeader++;
    }

    return 0;
}

static
BOOLEAN
LoadModule(
    IN OUT PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
    IN PCCH Path,
    IN PCCH ArcPath,
    IN PCCH File,
    IN PCCH ImportName, // BaseDllName
    IN TYPE_OF_MEMORY MemoryType,
    OUT PLDR_DATA_TABLE_ENTRY *Dte,
    IN ULONG Percentage,
    IN PVOID BaseAddress)
{
    BOOLEAN Success;
    CHAR FullFileName[MAX_PATH];
    CHAR ArcFileName[MAX_PATH];
    CHAR ProgressString[256];

    UiDrawBackdrop();
    RtlStringCbPrintfA(ProgressString, sizeof(ProgressString), "Loading %s...", File);
    UiDrawProgressBarCenter(Percentage, 100, ProgressString);

    RtlStringCbCopyA(FullFileName, sizeof(FullFileName), Path);
    RtlStringCbCatA(FullFileName, sizeof(FullFileName), File);

    RtlStringCbCopyA(ArcFileName, sizeof(ArcFileName), ArcPath);
    RtlStringCbCatA(ArcFileName, sizeof(ArcFileName), File);

    if (!BaseAddress)
    {
        Success = PeLdrLoadImage(ArcFileName, MemoryType, &BaseAddress);
        if (!Success)
        {
            TRACE("Loading %s failed\n", File);
            return FALSE;
        }
        TRACE("%s loaded successfully at %p\n", File, BaseAddress);
    }

    /*
     * Cheat about the base DLL name if we are loading
     * the Kernel Debugger Transport DLL, to make the
     * PE loader happy.
     */
    Success = PeLdrAllocateDataTableEntry(&LoaderBlock1->LoadOrderListHead,
                                          ImportName,
                                          FullFileName,
                                          BaseAddress,
                                          Dte);

    return Success;
}

static
BOOLEAN
LoadWindowsCore(IN USHORT OperatingSystemVersion,
                IN OUT PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
                IN PCSTR BootOptions,
                IN PCSTR BootPath,
                IN OUT PLDR_DATA_TABLE_ENTRY* KernelDTE,
                IN PVOID KernelAddress)
{
    BOOLEAN Success;
    PCSTR Options;
    CHAR ArcPath[MAX_PATH];
    CHAR HalFileName[MAX_PATH];
    CHAR KernelFileName[MAX_PATH];
    CHAR KdTransportDllName[MAX_PATH];
    PLDR_DATA_TABLE_ENTRY HalDTE, KdComDTE = NULL;

    static const CHAR DirPath[] = "\\SystemRoot\\system32\\";

    if (!KernelDTE) return FALSE;

    /* Initialize SystemRoot\System32 path */
    RtlStringCbCopyA(ArcPath, sizeof(ArcPath), BootPath);
    RtlStringCbCatA(ArcPath, sizeof(ArcPath), "system32\\");

    /*
     * Default HAL and KERNEL file names.
     * See the following links to know how the file names are actually chosen:
     * https://www.geoffchappell.com/notes/windows/boot/bcd/osloader/detecthal.htm
     * https://www.geoffchappell.com/notes/windows/boot/bcd/osloader/hal.htm
     * https://www.geoffchappell.com/notes/windows/boot/bcd/osloader/kernel.htm
     */
    RtlStringCbCopyA(HalFileName   , sizeof(HalFileName)   , "hal.dll");
    RtlStringCbCopyA(KernelFileName, sizeof(KernelFileName), "ntoskrnl.exe");

    /* Find any "/HAL=" or "/KERNEL=" switch in the boot options */
    Options = BootOptions;
    while (Options)
    {
        /* Skip possible initial whitespace */
        Options += strspn(Options, " \t");

        /* Check whether a new option starts and it is either HAL or KERNEL */
        if (*Options != '/' || (++Options,
            !(_strnicmp(Options, "HAL=",    4) == 0 ||
              _strnicmp(Options, "KERNEL=", 7) == 0)) )
        {
            /* Search for another whitespace */
            Options = strpbrk(Options, " \t");
            continue;
        }
        else
        {
            size_t i = strcspn(Options, " \t"); /* Skip whitespace */
            if (i == 0)
            {
                /* Use the default values */
                break;
            }

            /* We have found either HAL or KERNEL options */
            if (_strnicmp(Options, "HAL=", 4) == 0)
            {
                Options += 4; i -= 4;
                RtlStringCbCopyNA(HalFileName, sizeof(HalFileName), Options, i);
                _strupr(HalFileName);
            }
            else if (_strnicmp(Options, "KERNEL=", 7) == 0)
            {
                Options += 7; i -= 7;
                RtlStringCbCopyNA(KernelFileName, sizeof(KernelFileName), Options, i);
                _strupr(KernelFileName);
            }
        }
    }

    TRACE("HAL file = '%s' ; Kernel file = '%s'\n", HalFileName, KernelFileName);

    /* Load the Kernel */
    LoadModule(LoaderBlock1, DirPath, ArcPath, KernelFileName, "ntoskrnl.exe", LoaderSystemCode,
               KernelDTE, 30, KernelAddress);

    /* Load the HAL */
    LoadModule(LoaderBlock1, DirPath, ArcPath, HalFileName, "hal.dll", LoaderHalCode, &HalDTE,
               45, NULL);

    /* Load the Kernel Debugger Transport DLL */
    if (OperatingSystemVersion > _WIN32_WINNT_WIN2K)
    {
        /*
         * According to http://www.nynaeve.net/?p=173 :
         * "[...] Another enhancement that could be done Microsoft-side would be
         * a better interface for replacing KD transport modules. Right now, due
         * to the fact that ntoskrnl is static linked to KDCOM.DLL, the OS loader
         * has a hardcoded hack that interprets the KD type in the OS loader options,
         * loads one of the (hardcoded filenames) "kdcom.dll", "kd1394.dll", or
         * "kdusb2.dll" modules, and inserts them into the loaded module list under
         * the name "kdcom.dll". [...]"
         */

        /*
         * This loop replaces a dumb call to strstr(..., "DEBUGPORT=").
         * Indeed I want it to be case-insensitive to allow "debugport="
         * or "DeBuGpOrT=" or... , and I don't want it to match malformed
         * command-line options, such as:
         *
         * "...foo DEBUGPORT=xxx bar..."
         * "...foo/DEBUGPORT=xxx bar..."
         * "...foo/DEBUGPORT=bar..."
         *
         * i.e. the "DEBUGPORT=" switch must start with a slash and be separated
         * from the rest by whitespace, unless it begins the command-line, e.g.:
         *
         * "/DEBUGPORT=COM1 foo...bar..."
         * "...foo /DEBUGPORT=USB bar..."
         * or:
         * "...foo /DEBUGPORT= bar..."
         * (in that case, we default the port to COM).
         */
        Options = BootOptions;
        while (Options)
        {
            /* Skip possible initial whitespace */
            Options += strspn(Options, " \t");

            /* Check whether a new option starts and it is the DEBUGPORT one */
            if (*Options != '/' || _strnicmp(++Options, "DEBUGPORT=", 10) != 0)
            {
                /* Search for another whitespace */
                Options = strpbrk(Options, " \t");
                continue;
            }
            else
            {
                /* We found the DEBUGPORT option. Move to the port name. */
                Options += 10;
                break;
            }
        }

        if (Options)
        {
            /*
             * We have found the DEBUGPORT option. Parse the port name.
             * Format: /DEBUGPORT=COM1 or /DEBUGPORT=FILE:\Device\HarddiskX\PartitionY\debug.log or /DEBUGPORT=FOO
             * If we only have /DEBUGPORT= (i.e. without any port name), defaults it to "COM".
             */
            RtlStringCbCopyA(KdTransportDllName, sizeof(KdTransportDllName), "KD");
            if (_strnicmp(Options, "COM", 3) == 0 && '0' <= Options[3] && Options[3] <= '9')
            {
                RtlStringCbCatNA(KdTransportDllName, sizeof(KdTransportDllName), Options, 3);
            }
            else
            {
                size_t i = strcspn(Options, " \t:"); /* Skip valid separators: whitespace or colon */
                if (i == 0)
                    RtlStringCbCatA(KdTransportDllName, sizeof(KdTransportDllName), "COM");
                else
                    RtlStringCbCatNA(KdTransportDllName, sizeof(KdTransportDllName), Options, i);
            }
            RtlStringCbCatA(KdTransportDllName, sizeof(KdTransportDllName), ".DLL");
            _strupr(KdTransportDllName);

            /*
             * Load the transport DLL. Override the base DLL name of the
             * loaded transport DLL to the default "KDCOM.DLL" name.
             */
            LoadModule(LoaderBlock1, DirPath, ArcPath, KdTransportDllName, "kdcom.dll", LoaderSystemCode,
                       &KdComDTE, 60, NULL);
        }
    }

    /* Load all referenced DLLs for Kernel, HAL and Kernel Debugger Transport DLL */
    Success  = PeLdrScanImportDescriptorTable(&LoaderBlock1->LoadOrderListHead, DirPath, ArcPath, *KernelDTE);
    Success &= PeLdrScanImportDescriptorTable(&LoaderBlock1->LoadOrderListHead, DirPath, ArcPath, HalDTE);
    if (KdComDTE)
    {
        Success &= PeLdrScanImportDescriptorTable(&LoaderBlock1->LoadOrderListHead, DirPath, ArcPath, KdComDTE);
    }

    return Success;
}

static
BOOLEAN
WinLdrInitErrataInf(
    IN OUT PLOADER_PARAMETER_EXTENSION2 Extension2,
    IN USHORT OperatingSystemVersion,
    IN PCSTR SystemRoot)
{
    LONG rc;
    HKEY hKey;
    ULONG BufferSize;
    ULONG FileSize;
    PVOID PhysicalBase;
    WCHAR szFileName[80];
    CHAR ErrataFilePath[MAX_PATH];

    /* Open either the 'BiosInfo' (Windows <= 2003) or the 'Errata' (Vista+) key */
    if (OperatingSystemVersion >= _WIN32_WINNT_VISTA)
    {
        rc = RegOpenKey(NULL,
                        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Errata",
                        &hKey);
    }
    else // (OperatingSystemVersion <= _WIN32_WINNT_WS03)
    {
        rc = RegOpenKey(NULL,
                        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\BiosInfo",
                        &hKey);
    }
    if (rc != ERROR_SUCCESS)
    {
        WARN("Could not open the BiosInfo/Errata registry key (Error %u)\n", (int)rc);
        return FALSE;
    }

    /* Retrieve the INF file name value */
    BufferSize = sizeof(szFileName);
    rc = RegQueryValue(hKey, L"InfName", NULL, (PUCHAR)szFileName, &BufferSize);
    if (rc != ERROR_SUCCESS)
    {
        WARN("Could not retrieve the InfName value (Error %u)\n", (int)rc);
        return FALSE;
    }

    // TODO: "SystemBiosDate"

    RtlStringCbPrintfA(ErrataFilePath, sizeof(ErrataFilePath), "%s%s%S",
                       SystemRoot, "inf\\", szFileName);

    /* Load the INF file */
    PhysicalBase = WinLdrLoadModule(ErrataFilePath, &FileSize, LoaderRegistryData);
    if (!PhysicalBase)
    {
        WARN("Could not load '%s'\n", ErrataFilePath);
        return FALSE;
    }

    Extension2->EmInfFileImage = PaToVa(PhysicalBase);
    Extension2->EmInfFileSize  = FileSize;

    return TRUE;
}

BOOLEAN
LoadKernel(
    IN PCHAR BootOptions,
    IN PCHAR BootPath,
    OUT PVOID KernelAddress)
{
    PCHAR Options;
    CHAR FileName[MAX_PATH];
    CHAR ArcFileName[MAX_PATH];

    RtlStringCbCopyA(FileName, sizeof(FileName), "ntoskrnl.exe");

    /* Find any "/KERNEL=" switch in the boot options */
    Options = BootOptions;
    while (Options)
    {
        /* Skip possible initial whitespace */
        Options += strspn(Options, " \t");

        /* Check whether a new option starts and it is either HAL or KERNEL */
        if (*Options != '/' || (++Options,
            !(_strnicmp(Options, "KERNEL=", 7) == 0)) )
        {
            /* Search for another whitespace */
            Options = strpbrk(Options, " \t");
            continue;
        }
        else
        {
            size_t i = strcspn(Options, " \t"); /* Skip whitespace */
            if (i == 0)
            {
                /* Use the default values */
                break;
            }

            if (_strnicmp(Options, "KERNEL=", 7) == 0)
            {
                Options += 7; i -= 7;
                RtlStringCbCopyNA(FileName, sizeof(FileName), Options, i);
                _strupr(FileName);
            }
        }
    }

    TRACE("Kernel file = '%s'\n", FileName);

    RtlStringCbCopyA(ArcFileName, sizeof(ArcFileName), BootPath);
    RtlStringCbCatA(ArcFileName, sizeof(ArcFileName), "system32\\");
    RtlStringCbCatA(ArcFileName, sizeof(ArcFileName), FileName);

    return PeLdrLoadImage(ArcFileName, LoaderSystemCode, KernelAddress);
}

ARC_STATUS
LoadAndBootWindows(
    IN ULONG Argc,
    IN PCHAR Argv[],
    IN PCHAR Envp[])
{
    ARC_STATUS Status;
    PCSTR ArgValue;
    PCSTR SystemPartition;
    PCHAR File;
    BOOLEAN Success;
    USHORT OperatingSystemVersion;
    void* LoaderBlock;
    PLOADER_PARAMETER_BLOCK1 LoaderBlock1;
    PLOADER_PARAMETER_BLOCK2 LoaderBlock2;
    PSETUP_LOADER_BLOCK* SetupBlockPtr;
    PLOADER_PARAMETER_EXTENSION1 Extension1;
    PLOADER_PARAMETER_EXTENSION2 Extension2;
    CHAR BootPath[MAX_PATH];
    CHAR FileName[MAX_PATH];
    CHAR BootOptions[256];
    PVOID KernelAddress;

    /* Retrieve the (mandatory) system partition */
    SystemPartition = GetArgumentValue(Argc, Argv, "SystemPartition");
    if (!SystemPartition || !*SystemPartition)
    {
        ERR("No 'SystemPartition' specified, aborting!\n");
        return EINVAL;
    }

    UiDrawBackdrop();
    UiDrawProgressBarCenter(1, 100, "Loading NT...");

    /* Retrieve the system path */
    *BootPath = ANSI_NULL;
    ArgValue = GetArgumentValue(Argc, Argv, "SystemPath");
    if (ArgValue)
        RtlStringCbCopyA(BootPath, sizeof(BootPath), ArgValue);

    /*
     * Check whether BootPath is a full path
     * and if not, create a full boot path.
     *
     * See FsOpenFile for the technique used.
     */
    if (strrchr(BootPath, ')') == NULL)
    {
        /* Temporarily save the boot path */
        RtlStringCbCopyA(FileName, sizeof(FileName), BootPath);

        /* This is not a full path: prepend the SystemPartition */
        RtlStringCbCopyA(BootPath, sizeof(BootPath), SystemPartition);

        /* Append a path separator if needed */
        if (*FileName != '\\' && *FileName != '/')
            RtlStringCbCatA(BootPath, sizeof(BootPath), "\\");

        /* Append the remaining path */
        RtlStringCbCatA(BootPath, sizeof(BootPath), FileName);
    }

    /* Append a path separator if needed */
    if (!*BootPath || BootPath[strlen(BootPath) - 1] != '\\')
        RtlStringCbCatA(BootPath, sizeof(BootPath), "\\");

    TRACE("BootPath: '%s'\n", BootPath);

    /* Retrieve the boot options */
    *BootOptions = ANSI_NULL;
    ArgValue = GetArgumentValue(Argc, Argv, "Options");
    if (ArgValue && *ArgValue)
        RtlStringCbCopyA(BootOptions, sizeof(BootOptions), ArgValue);

    /* Append boot-time options */
    AppendBootTimeOptions(BootOptions);

    /*
     * Set "/HAL=" and "/KERNEL=" options if needed.
     * If already present on the standard "Options=" option line, they take
     * precedence over those passed via the separate "Hal=" and "Kernel="
     * options.
     */
    if (strstr(BootOptions, "/HAL=") != 0)
    {
        /*
         * Not found in the options, try to retrieve the
         * separate value and append it to the options.
         */
        ArgValue = GetArgumentValue(Argc, Argv, "Hal");
        if (ArgValue && *ArgValue)
        {
            RtlStringCbCatA(BootOptions, sizeof(BootOptions), " /HAL=");
            RtlStringCbCatA(BootOptions, sizeof(BootOptions), ArgValue);
        }
    }
    if (strstr(BootOptions, "/KERNEL=") != 0)
    {
        /*
         * Not found in the options, try to retrieve the
         * separate value and append it to the options.
         */
        ArgValue = GetArgumentValue(Argc, Argv, "Kernel");
        if (ArgValue && *ArgValue)
        {
            RtlStringCbCatA(BootOptions, sizeof(BootOptions), " /KERNEL=");
            RtlStringCbCatA(BootOptions, sizeof(BootOptions), ArgValue);
        }
    }

    TRACE("BootOptions: '%s'\n", BootOptions);

    /* Check if a ramdisk file was given */
    File = strstr(BootOptions, "/RDPATH=");
    if (File)
    {
        /* Load the ramdisk */
        Status = RamDiskInitialize(FALSE, BootOptions, SystemPartition);
        if (Status != ESUCCESS)
        {
            File += 8;
            UiMessageBox("Failed to load RAM disk file '%.*s'",
                         strcspn(File, " \t"), File);
            return Status;
        }
    }

    /* Let user know we started loading */
    //UiDrawStatusText("Loading...");

    if (!LoadKernel(BootOptions, BootPath, &KernelAddress))
    {
        UiMessageBox("Failed to load kernel");
        return EINVAL;
    }

    /* Find the version number from the kernel */
    OperatingSystemVersion = WinLdrDetectVersion(KernelAddress);
    if (OperatingSystemVersion == 0)
    {
        UiMessageBox("Could not detect kernel version");
        return EINVAL;
    }

    /* Allocate and minimally-initialize the Loader Parameter Block */
    AllocateAndInitLPB(OperatingSystemVersion, &LoaderBlock, &LoaderBlock1,
                       &LoaderBlock2, &SetupBlockPtr, &Extension1, &Extension2);

    /* Load the system hive */
    UiDrawBackdrop();
    UiDrawProgressBarCenter(15, 100, "Loading system hive...");
    Success = WinLdrInitSystemHive(LoaderBlock1, BootPath, FALSE);
    TRACE("SYSTEM hive %s\n", (Success ? "loaded" : "not loaded"));
    /* Bail out if failure */
    if (!Success)
        return ENOEXEC;

    /* Load NLS data, OEM font, and prepare boot drivers list */
    Success = WinLdrScanSystemHive(LoaderBlock1, BootPath);
    TRACE("SYSTEM hive %s\n", (Success ? "scanned" : "not scanned"));
    /* Bail out if failure */
    if (!Success)
        return ENOEXEC;

    /* Load the Firmware Errata file */
    Success = WinLdrInitErrataInf(Extension2, OperatingSystemVersion, BootPath);
    TRACE("Firmware Errata file %s\n", (Success ? "loaded" : "not loaded"));
    /* Not necessarily fatal if not found - carry on going */

    /* Finish loading */
    return LoadAndBootWindowsCommon(OperatingSystemVersion,
                                    LoaderBlock,
                                    LoaderBlock1,
                                    LoaderBlock2,
                                    SetupBlockPtr,
                                    Extension1,
                                    Extension2,
                                    BootOptions,
                                    BootPath,
                                    FALSE,
                                    KernelAddress);
}

ARC_STATUS
LoadAndBootWindowsCommon(
    USHORT OperatingSystemVersion,
    void* LoaderBlock,
    PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
    PLOADER_PARAMETER_BLOCK2 LoaderBlock2,
    PSETUP_LOADER_BLOCK* SetupBlockPtr,
    PLOADER_PARAMETER_EXTENSION1 Extension1,
    PLOADER_PARAMETER_EXTENSION2 Extension2,
    PCSTR BootOptions,
    PCSTR BootPath,
    BOOLEAN Setup,
    PVOID KernelAddress)
{
    void* LoaderBlockVA;
    BOOLEAN Success;
    PLDR_DATA_TABLE_ENTRY KernelDTE;
    KERNEL_ENTRY_POINT KiSystemStartup;
    PCSTR SystemRoot;

    TRACE("LoadAndBootWindowsCommon()\n");

    ASSERT(OperatingSystemVersion != 0);

#ifdef _M_IX86
    /* Setup redirection support */
    WinLdrSetupEms((PCHAR)BootOptions);
#endif

    /* Convert BootPath to SystemRoot */
    SystemRoot = strstr(BootPath, "\\");

    /* Detect hardware */
    UiDrawBackdrop();
    UiDrawProgressBarCenter(20, 100, "Detecting hardware...");
    LoaderBlock1->ConfigurationRoot = MachHwDetect();

    /* Load the operating system core: the Kernel, the HAL and the Kernel Debugger Transport DLL */
    Success = LoadWindowsCore(OperatingSystemVersion,
                              LoaderBlock1,
                              BootOptions,
                              BootPath,
                              &KernelDTE,
                              KernelAddress);
    if (!Success)
    {
        UiMessageBox("Error loading NTOS core.");
        return ENOEXEC;
    }

    /* Load boot drivers */
    UiDrawBackdrop();
    UiDrawProgressBarCenter(100, 100, "Loading boot drivers...");
    Success = WinLdrLoadBootDrivers(LoaderBlock1, BootPath);
    TRACE("Boot drivers loading %s\n", Success ? "successful" : "failed");

    /* Cleanup ini file */
    IniCleanup();

    /* Initialize Phase 1 - no drivers loading anymore */
    WinLdrInitializePhase1(LoaderBlock1,
                           LoaderBlock2,
                           SetupBlockPtr,
                           Extension1,
                           Extension2,
                           BootOptions,
                           SystemRoot,
                           BootPath,
                           OperatingSystemVersion);

    /* Save entry-point pointer and Loader block VAs */
    KiSystemStartup = (KERNEL_ENTRY_POINT)KernelDTE->EntryPoint;
    LoaderBlockVA = PaToVa(LoaderBlock);

    /* "Stop all motors", change videomode */
    MachPrepareForReactOS();

    /* Debugging... */
    //DumpMemoryAllocMap();

    /* Do the machine specific initialization */
    WinLdrSetupMachineDependent(LoaderBlock2);

    /* Map pages and create memory descriptors */
    WinLdrSetupMemoryLayout(LoaderBlock1);

    /* Set processor context */
    WinLdrSetProcessorContext(OperatingSystemVersion);

    /* Save final value of LoaderPagesSpanned */
    Extension2->LoaderPagesSpanned = LoaderPagesSpanned;

    TRACE("Hello from paged mode, KiSystemStartup %p, LoaderBlockVA %p!\n",
          KiSystemStartup, LoaderBlockVA);

    /* Zero KI_USER_SHARED_DATA page */
    RtlZeroMemory((PVOID)KI_USER_SHARED_DATA, MM_PAGE_SIZE);

    WinLdrpDumpMemoryDescriptors(PaToVa(LoaderBlock1));
    WinLdrpDumpBootDriver(PaToVa(LoaderBlock1));
#ifndef _M_AMD64
    WinLdrpDumpArcDisks(PaToVa(LoaderBlock1), OperatingSystemVersion);
#endif

    /* Pass control */
    (*KiSystemStartup)(LoaderBlockVA);
    return ESUCCESS;
}

VOID
WinLdrpDumpMemoryDescriptors(PLOADER_PARAMETER_BLOCK1 LoaderBlock1)
{
    PLIST_ENTRY NextMd;
    PMEMORY_ALLOCATION_DESCRIPTOR MemoryDescriptor;

    NextMd = LoaderBlock1->MemoryDescriptorListHead.Flink;

    while (NextMd != &LoaderBlock1->MemoryDescriptorListHead)
    {
        MemoryDescriptor = CONTAINING_RECORD(NextMd, MEMORY_ALLOCATION_DESCRIPTOR, ListEntry);

        TRACE("BP %08X PC %04X MT %d\n", MemoryDescriptor->BasePage,
            MemoryDescriptor->PageCount, MemoryDescriptor->MemoryType);

        NextMd = MemoryDescriptor->ListEntry.Flink;
    }
}

VOID
WinLdrpDumpBootDriver(PLOADER_PARAMETER_BLOCK1 LoaderBlock1)
{
    PLIST_ENTRY NextBd;
    PBOOT_DRIVER_LIST_ENTRY BootDriver;

    NextBd = LoaderBlock1->BootDriverListHead.Flink;

    while (NextBd != &LoaderBlock1->BootDriverListHead)
    {
        BootDriver = CONTAINING_RECORD(NextBd, BOOT_DRIVER_LIST_ENTRY, Link);

        TRACE("BootDriver %wZ DTE %08X RegPath: %wZ\n", &BootDriver->FilePath,
            BootDriver->LdrEntry, &BootDriver->RegistryPath);

        NextBd = BootDriver->Link.Flink;
    }
}

VOID
WinLdrpDumpArcDisks(PLOADER_PARAMETER_BLOCK1 LoaderBlock1, USHORT OperatingSystemVersion)
{
    PLIST_ENTRY NextBd;

    NextBd = LoaderBlock1->ArcDiskInformation->DiskSignatureListHead.Flink;

    while (NextBd != &LoaderBlock1->ArcDiskInformation->DiskSignatureListHead)
    {
        if (OperatingSystemVersion >= _WIN32_WINNT_WIN7)
        {
            PARC_DISK_SIGNATURE_WIN7 ArcDisk = CONTAINING_RECORD(NextBd, ARC_DISK_SIGNATURE_WIN7, ListEntry);

            TRACE("ArcDisk %s checksum: 0x%X, signature: 0x%X\n",
                  ArcDisk->ArcName, ArcDisk->CheckSum, ArcDisk->Signature);

            NextBd = ArcDisk->ListEntry.Flink;
        }
        else
        {
            PARC_DISK_SIGNATURE ArcDisk = CONTAINING_RECORD(NextBd, ARC_DISK_SIGNATURE, ListEntry);

            TRACE("ArcDisk %s checksum: 0x%X, signature: 0x%X\n",
                  ArcDisk->ArcName, ArcDisk->CheckSum, ArcDisk->Signature);

            NextBd = ArcDisk->ListEntry.Flink;
        }
    }
}
