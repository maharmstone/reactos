/*
 * PROJECT:     FreeLoader
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Windows-compatible NT OS Loader.
 * COPYRIGHT:   Copyright 2006-2019 Aleksey Bragin <aleksey@reactos.org>
 */

#pragma once

#include <arc/setupblk.h>

/* Entry-point to kernel */
typedef VOID (NTAPI *KERNEL_ENTRY_POINT) (PLOADER_PARAMETER_BLOCK LoaderBlock);

/* Descriptors */
#define NUM_GDT 128     // Must be 128
#define NUM_IDT 0x100   // Only 16 are used though. Must be 0x100

#if 0

#include <pshpack1.h>
typedef struct  /* Root System Descriptor Pointer */
{
    CHAR             signature [8];          /* contains "RSD PTR " */
    UCHAR            checksum;               /* to make sum of struct == 0 */
    CHAR             oem_id [6];             /* OEM identification */
    UCHAR            revision;               /* Must be 0 for 1.0, 2 for 2.0 */
    ULONG            rsdt_physical_address;  /* 32-bit physical address of RSDT */
    ULONG            length;                 /* XSDT Length in bytes including hdr */
    ULONGLONG        xsdt_physical_address;  /* 64-bit physical address of XSDT */
    UCHAR            extended_checksum;      /* Checksum of entire table */
    CHAR             reserved [3];           /* reserved field must be 0 */
} RSDP_DESCRIPTOR, *PRSDP_DESCRIPTOR;
#include <poppack.h>

typedef struct _ARC_DISK_SIGNATURE_EX
{
    ARC_DISK_SIGNATURE DiskSignature;
    CHAR ArcName[MAX_PATH];
} ARC_DISK_SIGNATURE_EX, *PARC_DISK_SIGNATURE_EX;

#endif

#define MAX_OPTIONS_LENGTH 255

typedef struct _LOADER_PARAMETER_BLOCK1
{
    LIST_ENTRY LoadOrderListHead;
    LIST_ENTRY MemoryDescriptorListHead;
    LIST_ENTRY BootDriverListHead;
    ULONG_PTR KernelStack;
    ULONG_PTR Prcb;
    ULONG_PTR Process;
    ULONG_PTR Thread;
    ULONG RegistryLength;
    PVOID RegistryBase;
    PCONFIGURATION_COMPONENT_DATA ConfigurationRoot;
    PSTR ArcBootDeviceName;
    PSTR ArcHalDeviceName;
    PSTR NtBootPathName;
    PSTR NtHalPathName;
    PSTR LoadOptions;
    PNLS_DATA_BLOCK NlsData;
    PARC_DISK_INFORMATION ArcDiskInformation;
    PVOID OemFontFile;
} LOADER_PARAMETER_BLOCK1, *PLOADER_PARAMETER_BLOCK1;

typedef struct _LOADER_PARAMETER_BLOCK2
{
    PLOADER_PARAMETER_EXTENSION Extension;
    union
    {
        I386_LOADER_BLOCK I386;
        ALPHA_LOADER_BLOCK Alpha;
        IA64_LOADER_BLOCK IA64;
        PPC_LOADER_BLOCK PowerPC;
        ARM_LOADER_BLOCK Arm;
    } u;
    FIRMWARE_INFORMATION_LOADER_BLOCK FirmwareInformation;
} LOADER_PARAMETER_BLOCK2, *PLOADER_PARAMETER_BLOCK2;

typedef struct _LOADER_PARAMETER_BLOCK_VISTA
{
    LOADER_PARAMETER_BLOCK1 Block1;
    PSETUP_LOADER_BLOCK SetupLdrBlock;
    LOADER_PARAMETER_BLOCK2 Block2;
} LOADER_PARAMETER_BLOCK_VISTA, *PLOADER_PARAMETER_BLOCK_VISTA;

typedef struct _LOADER_PARAMETER_BLOCK_WIN7
{
    ULONG OsMajorVersion;
    ULONG OsMinorVersion;
    ULONG Size;
    ULONG Reserved;
    LOADER_PARAMETER_BLOCK1 Block1;
    LOADER_PARAMETER_BLOCK2 Block2;
} LOADER_PARAMETER_BLOCK_WIN7, *PLOADER_PARAMETER_BLOCK_WIN7;

typedef struct _LOADER_PARAMETER_EXTENSION1
{
    ULONG Size;
    PROFILE_PARAMETER_BLOCK Profile;
} LOADER_PARAMETER_EXTENSION1, *PLOADER_PARAMETER_EXTENSION1;

#pragma pack(push)
#pragma pack(1)

typedef struct _LOADER_PARAMETER_EXTENSION2
{
    PVOID EmInfFileImage;
    ULONG EmInfFileSize;
    PVOID TriageDumpBlock;
    //
    // NT 5.1
    //
    ULONG_PTR LoaderPagesSpanned;   /* Not anymore present starting NT 6.2 */
    PHEADLESS_LOADER_BLOCK HeadlessLoaderBlock;
    PSMBIOS_TABLE_HEADER SMBiosEPSHeader;
    PVOID DrvDBImage;
    ULONG DrvDBSize;
    PNETWORK_LOADER_BLOCK NetworkLoaderBlock;
    //
    // NT 5.2+
    //
#ifdef _X86_
    PUCHAR HalpIRQLToTPR;
    PUCHAR HalpVectorToIRQL;
#endif
    LIST_ENTRY FirmwareDescriptorListHead;
    PVOID AcpiTable;
    ULONG AcpiTableSize;
    //
    // NT 5.2 SP1+
    //
/** NT-version-dependent flags **/
    ULONG BootViaWinload:1;
    ULONG BootViaEFI:1;
    ULONG Reserved:30;
/********************************/
    PLOADER_PERFORMANCE_DATA LoaderPerformanceData;
    LIST_ENTRY BootApplicationPersistentData;
    PVOID WmdTestResult;
    GUID BootIdentifier;
    //
    // NT 6
    //
    ULONG ResumePages;
    PVOID DumpHeader;
    PVOID BgContext;
    PVOID NumaLocalityInfo;
    PVOID NumaGroupAssignment;
    LIST_ENTRY AttachedHives;
    ULONG MemoryCachingRequirementsCount;
    PVOID MemoryCachingRequirements;
    TPM_BOOT_ENTROPY_LDR_RESULT TpmBootEntropyResult;
    ULONGLONG ProcessorCounterFrequency;
} LOADER_PARAMETER_EXTENSION2, *PLOADER_PARAMETER_EXTENSION2;

typedef struct _LOADER_PARAMETER_EXTENSION_VISTA
{
    LOADER_PARAMETER_EXTENSION1 Extension1;
    ULONG MajorVersion;
    ULONG MinorVersion;
    LOADER_PARAMETER_EXTENSION2 Extension2;
} LOADER_PARAMETER_EXTENSION_VISTA, *PLOADER_PARAMETER_EXTENSION_VISTA;

typedef struct _LOADER_PARAMETER_EXTENSION_WIN7
{
    LOADER_PARAMETER_EXTENSION1 Extension1;
    LOADER_PARAMETER_EXTENSION2 Extension2;
} LOADER_PARAMETER_EXTENSION_WIN7, *PLOADER_PARAMETER_EXTENSION_WIN7;

#pragma pack(pop)

typedef struct _LOADER_SYSTEM_BLOCK
{
    union
    {
        LOADER_PARAMETER_BLOCK_VISTA LoaderBlockVista;
        LOADER_PARAMETER_BLOCK_WIN7 LoaderBlockWin7;
    } u1;

    union
    {
        LOADER_PARAMETER_EXTENSION_VISTA ExtensionVista;
        LOADER_PARAMETER_EXTENSION_WIN7 ExtensionWin7;
    } u2;

    SETUP_LOADER_BLOCK SetupBlock;
#ifdef _M_IX86
    HEADLESS_LOADER_BLOCK HeadlessLoaderBlock;
#endif
    NLS_DATA_BLOCK NlsDataBlock;
    CHAR LoadOptions[MAX_OPTIONS_LENGTH+1];
    CHAR ArcBootDeviceName[MAX_PATH+1];
    // CHAR ArcHalDeviceName[MAX_PATH];
    CHAR NtBootPathName[MAX_PATH+1];
    CHAR NtHalPathName[MAX_PATH+1];
    ARC_DISK_INFORMATION ArcDiskInformation;
    LOADER_PERFORMANCE_DATA LoaderPerformanceData;
} LOADER_SYSTEM_BLOCK, *PLOADER_SYSTEM_BLOCK;

extern PLOADER_SYSTEM_BLOCK WinLdrSystemBlock;


// conversion.c
#if 0
PVOID VaToPa(PVOID Va);
PVOID PaToVa(PVOID Pa);
VOID List_PaToVa(_In_ LIST_ENTRY *ListEntry);
#endif
VOID ConvertConfigToVA(PCONFIGURATION_COMPONENT_DATA Start);


// winldr.c
PVOID WinLdrLoadModule(PCSTR ModuleName, PULONG Size,
                       TYPE_OF_MEMORY MemoryType);

// wlmemory.c
BOOLEAN
WinLdrSetupMemoryLayout(IN OUT PLOADER_PARAMETER_BLOCK1 LoaderBlock1);

// wlregistry.c
BOOLEAN
WinLdrInitSystemHive(
    IN OUT PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
    IN PCSTR SystemRoot,
    IN BOOLEAN Setup);

BOOLEAN WinLdrScanSystemHive(IN OUT PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
                             IN PCSTR SystemRoot);

// winldr.c
VOID
WinLdrInitializePhase1(PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
                       PLOADER_PARAMETER_BLOCK2 LoaderBlock2,
                       PSETUP_LOADER_BLOCK* SetupBlockPtr,
                       PLOADER_PARAMETER_EXTENSION1 Extension1,
                       PLOADER_PARAMETER_EXTENSION2 Extension2,
                       PCSTR Options,
                       PCSTR SystemPath,
                       PCSTR BootPath,
                       USHORT VersionToBoot);
BOOLEAN
WinLdrLoadNLSData(IN OUT PLOADER_PARAMETER_BLOCK1 LoaderBlock1,
                  IN PCSTR DirectoryPath,
                  IN PCSTR AnsiFileName,
                  IN PCSTR OemFileName,
                  IN PCSTR LanguageFileName);
BOOLEAN
WinLdrAddDriverToList(LIST_ENTRY *BootDriverListHead,
                      PWSTR RegistryPath,
                      PWSTR ImagePath,
                      PWSTR ServiceName,
                      PWSTR GroupName,
                      ULONG ErrorControl,
                      ULONG Tag);

VOID
WinLdrpDumpMemoryDescriptors(PLOADER_PARAMETER_BLOCK1 LoaderBlock1);

VOID
WinLdrpDumpBootDriver(PLOADER_PARAMETER_BLOCK1 LoaderBlock1);

VOID
WinLdrpDumpArcDisks(PLOADER_PARAMETER_BLOCK1 LoaderBlock1, USHORT OperatingSystemVersion);

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
    BOOLEAN Setup);

VOID
WinLdrSetupMachineDependent(PLOADER_PARAMETER_BLOCK2 LoaderBlock2);

VOID
WinLdrSetProcessorContext(USHORT OperatingSystemVersion);

// arch/xxx/winldr.c
BOOLEAN
MempSetupPaging(IN PFN_NUMBER StartPage,
                IN PFN_NUMBER NumberOfPages,
                IN BOOLEAN KernelMapping);

VOID
MempUnmapPage(PFN_NUMBER Page);

VOID
MempDump(VOID);
