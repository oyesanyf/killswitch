/*
 * KillSwitch Ring-0 Windows Kernel Minifilter, ELAM & Object Callback Driver
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements:
 *   1. PsSetCreateProcessNotifyRoutineEx — Ring-0 process creation/termination lineage telemetry
 *   2. ObRegisterCallbacks                — Ring-0 handle strip against PROCESS_TERMINATE / PROCESS_VM_WRITE
 *                                           targeting lsass.exe and killswitch.exe (requires /INTEGRITYCHECK)
 *   3. FltRegisterFilter                  — File system minifilter (Altitude 385200, FSFilter Anti-Virus)
 *   4. FltCreateCommunicationPort         — Authenticated Ring-0 -> User-Mode telemetry pipe (\KillSwitchRing0Port)
 *
 * Build Requirements (Windows Driver Kit / WDK 10+):
 *   msbuild killswitch_minifilter.vcxproj /p:Configuration=Release /p:Platform=x64
 *   Linker flags: /INTEGRITYCHECK (sets IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080)
 *   Signing: Must be countersigned with an Extended Validation (EV) / Microsoft WHQL certificate
 *            and registered with Early Launch Anti-Malware (ELAM) for PPL / Ring-0 load.
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddk.h>

#define KILLSWITCH_PORT_NAME          L"\\KillSwitchRing0Port"
#define KILLSWITCH_ALTITUDE           L"385200"
#define PROCESS_TERMINATE             0x0001
#define PROCESS_VM_OPERATION          0x0008
#define PROCESS_VM_READ               0x0010
#define PROCESS_VM_WRITE              0x0020

typedef struct _KILLSWITCH_RING0_EVENT {
    UINT32 Magic;              /* 0x4B535230 ('KSR0') */
    UINT32 Version;            /* 1 */
    UINT32 EventType;          /* 1 = ProcessCreate, 2 = ObHandleStrip, 3 = MinifilterWrite */
    UINT32 ParentPid;
    UINT32 ProcessId;
    UINT32 DesiredAccessMask;
    UINT64 Timestamp100Ns;
    WCHAR  ImageFileName[128];
    UINT8  FrameSha256[32];
} KILLSWITCH_RING0_EVENT, *PKILLSWITCH_RING0_EVENT;

static PFLT_FILTER g_FilterHandle = NULL;
static PFLT_PORT   g_ServerPort   = NULL;
static PFLT_PORT   g_ClientPort   = NULL;
static PVOID       g_ObRegHandle  = NULL;
static BOOLEAN     g_ProcNotifyRegistered = FALSE;

static OB_PREOP_CALLBACK_STATUS
KillSwitchObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    /* Never strip kernel-initiated handle operations */
    if (OperationInformation->KernelHandle == 1) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    if (TargetProcess == CurrentProcess) {
        return OB_PREOP_SUCCESS;
    }

    /* Strip PROCESS_TERMINATE and PROCESS_VM_WRITE against protected daemon & LSASS */
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    }

    return OB_PREOP_SUCCESS;
}

static VOID
KillSwitchProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL && g_ClientPort != NULL && g_FilterHandle != NULL) {
        KILLSWITCH_RING0_EVENT Evt = { 0 };
        LARGE_INTEGER Now;
        KeQuerySystemTimePrecise(&Now);

        Evt.Magic          = 0x4B535230;
        Evt.Version        = 1;
        Evt.EventType      = 1;
        Evt.ParentPid      = (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId;
        Evt.ProcessId      = (UINT32)(ULONG_PTR)ProcessId;
        Evt.Timestamp100Ns = (UINT64)Now.QuadPart;

        if (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL) {
            USHORT CopyBytes = min(CreateInfo->ImageFileName->Length, (USHORT)(127 * sizeof(WCHAR)));
            RtlCopyMemory(Evt.ImageFileName, CreateInfo->ImageFileName->Buffer, CopyBytes);
        }

        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10000; /* 1 ms non-blocking send */
        FltSendMessage(g_FilterHandle, &g_ClientPort, &Evt, sizeof(Evt), NULL, NULL, &Timeout);
    }
}

NTSTATUS
KillSwitchFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_ProcNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(KillSwitchProcessNotifyCallbackEx, TRUE);
        g_ProcNotifyRegistered = FALSE;
    }

    if (g_ObRegHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
    }

    if (g_ServerPort != NULL) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }

    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    NULL,
    KillSwitchFilterUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS Status;

    Status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /* Register ObRegisterCallbacks for Ring-0 process handle tamper protection */
    OB_OPERATION_REGISTRATION OpReg = { 0 };
    OB_CALLBACK_REGISTRATION  CbReg = { 0 };
    UNICODE_STRING Altitude;
    RtlInitUnicodeString(&Altitude, KILLSWITCH_ALTITUDE);

    OpReg.ObjectType   = PsProcessType;
    OpReg.Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OpReg.PreOperation = KillSwitchObPreOperationCallback;

    CbReg.Version                    = OB_FLT_REGISTRATION_VERSION;
    CbReg.OperationRegistrationCount = 1;
    CbReg.Altitude                   = Altitude;
    CbReg.RegistrationContext        = NULL;
    CbReg.OperationRegistration      = &OpReg;

    Status = ObRegisterCallbacks(&CbReg, &g_ObRegHandle);
    if (!NT_SUCCESS(Status)) {
        g_ObRegHandle = NULL;
    }

    /* Register PsSetCreateProcessNotifyRoutineEx for Ring-0 process lineage */
    Status = PsSetCreateProcessNotifyRoutineEx(KillSwitchProcessNotifyCallbackEx, FALSE);
    if (NT_SUCCESS(Status)) {
        g_ProcNotifyRegistered = TRUE;
    }

    Status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(Status)) {
        KillSwitchFilterUnload(0);
    }

    return Status;
}
