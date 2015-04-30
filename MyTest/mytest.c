// #include <ntddk.h>
#include <ntifs.h>
#include <initguid.h>
#include "public.h"
#include "errlog.h"
#include "mytest.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
// #pragma alloc_text (PAGE, MyUnload)
#endif

#define UNITS_100NS_PER_SEC  (10 * 1000 * 1000)

__inline static LARGE_INTEGER 
longToLargeInteger(long value)
{
    LARGE_INTEGER li;
    * (__int64*) & li= (__int64) value;
    return li;
}

__inline static uint64_t
largeInteger_to_uint64(LARGE_INTEGER* p)
{
    return * (uint64_t*) p;
}

// {23D27648-B3D7-42fc-9FE1-644404A4540A}
DEFINE_GUID(COMPONENT_GUID, 0x23d27648, 0xb3d7, 0x42fc, 0x9f, 0xe1, 0x64, 0x44, 0x4, 0xa4, 0x54, 0xa);

static DRIVER_OBJECT* s_DriverObject = NULL;
static KBUGCHECK_REASON_CALLBACK_RECORD s_BugcheckReasonCallbackRecord;
static KBUGCHECK_REASON_CALLBACK_ROUTINE BugCheckSecondaryDumpDataCallback;
static const char* s_panic_string = NULL;
static int s_panic_strlen = 0;

static KDEFERRED_ROUTINE TimerRoutine;
static KSTART_ROUTINE ThreadMain;
static VOID UninitDevice(DEVICE_OBJECT* DeviceObject);
static VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
static VOID* copyin_alloc(const VOID* va, ULONG size, ULONG extraSize, ULONG minSize, ULONG maxSize, KPROCESSOR_MODE RequestorMode, NTSTATUS* pstatus);

static NTSTATUS 
__drv_maxIRQL(DISPATCH_LEVEL)
logSystemMessage(const char* messageText);

NTSTATUS
DriverEntry(DRIVER_OBJECT* DriverObject, 
            UNICODE_STRING* RegistryPath)
{
    PDEVICE_OBJECT      deviceObject;
    PDEVICE_EXTENSION   deviceExtension;
    UNICODE_STRING      ntDeviceName;
    UNICODE_STRING      symbolicLinkName;
    NTSTATUS            status;
    int                 k;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("%s ==> DriverEntry\n", DbgPrefix);

    s_DriverObject = DriverObject;

    KeInitializeCallbackRecord(& s_BugcheckReasonCallbackRecord);
    if (! KeRegisterBugCheckReasonCallback(& s_BugcheckReasonCallbackRecord,
                                           BugCheckSecondaryDumpDataCallback,
                                           KbCallbackSecondaryDumpData,
                                           (unsigned char*) COMPONENT_NAME))
    {
        DbgPrint("%s Unable to register bugcheck callback\n", DbgPrefix);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 192 bytes on Windows 7 x64, equals to 95 Unicode chars longest text message, less on x86
    // can be down to 51 characters on earlier versions of Windows
    DbgPrint("%s errlog packet variable area max size = %d bytes\n", DbgPrefix, (int) (ERROR_LOG_MAXIMUM_SIZE - sizeof(IO_ERROR_LOG_PACKET)));

    DbgPrint("%s short = %d bytes\n", DbgPrefix, sizeof(short));           // 2
    DbgPrint("%s int = %d bytes\n", DbgPrefix, sizeof(int));               // 4
    DbgPrint("%s long = %d bytes\n", DbgPrefix, sizeof(long));             // 4
    DbgPrint("%s long long = %d bytes\n", DbgPrefix, sizeof(long long));   // 8

    /* 
     * Create the device object 
     */
    RtlInitUnicodeString(&ntDeviceName, NTDEVICE_NAME_STRING);

    status = IoCreateDevice(DriverObject,               // DriverObject
                            sizeof(DEVICE_EXTENSION),   // DeviceExtensionSize
                            &ntDeviceName,              // DeviceName
                            FILE_DEVICE_UNKNOWN,        // DeviceType
                            FILE_DEVICE_SECURE_OPEN,    // DeviceCharacteristics
                            FALSE,                      // Not Exclusive
                            &deviceObject);             // DeviceObject

    if (! NT_SUCCESS(status))
    {
        DbgPrint("%s IoCreateDevice returned 0x%x\n", DbgPrefix, status);
        return status;
    }

    /*
     * Set up dispatch entry points for the driver.
     */
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = MyDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = MyDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_READ]            = MyDispatchRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE]           = MyDispatchWrite;
    // DriverObject->MajorFunction[IRP_MJ_CLEANUP]         = MyDipatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = MyDispatchIoControl;
    DriverObject->DriverUnload                          = MyUnload;

    /*
     * Initialize the device extension.
     */
    deviceExtension = deviceObject->DeviceExtension;
    RtlZeroMemory(deviceExtension, sizeof(DEVICE_EXTENSION));
    deviceExtension->deviceObject = deviceObject;
    deviceExtension->dataBuffer = NULL;
    deviceExtension->dataSize = 0;
    deviceExtension->dataLockInitialized = FALSE;
    status = ExInitializeResourceLite(& deviceExtension->dataLock);
    if (! NT_SUCCESS(status))
    {
        UninitDevice(deviceObject);
        IoDeleteDevice(deviceObject);
        DbgPrint("%s ExInitializeResourceLite returned 0x%x\n", DbgPrefix, status);
        return status;
    }
    deviceExtension->dataLockInitialized = TRUE;

    /* initialize and start timers */
    for (k = 0;  k < NTIMERS;  k++)
    {
        TimerObject* timer = & deviceExtension->timers[k];
        timer->cancel = FALSE;
        timer->context1 = k;
        timer->context2 = 0;
        KeInitializeSpinLock(& timer->timerLock);
        KeInitializeDpc(& timer->timerDpc, TimerRoutine, timer);
        KeInitializeTimerEx(& timer->timer, NotificationTimer);
        KeSetTimer(& timer->timer, longToLargeInteger(-8 * UNITS_100NS_PER_SEC), & timer->timerDpc);
    }

    /* install thread creation/deletion notify routine */
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (! NT_SUCCESS(status))
    {
        DbgPrint("%s failed to install thread notify routine, code: %08X\n", DbgPrefix, status);
    }

    /* initialize and start threads */
    for (k = 0;  k < NTHREADS;  k++)
    {
        OBJECT_ATTRIBUTES oa;
        HANDLE threadHandle = NULL;

        ThreadInfo* tinfo = & deviceExtension->threads[k];
        tinfo->context1 = k;
        KeInitializeEvent(& tinfo->exitEvent, NotificationEvent, FALSE);

        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        status = PsCreateSystemThread(& threadHandle, THREAD_ALL_ACCESS, & oa, NULL, NULL, ThreadMain, tinfo);

        if (NT_SUCCESS(status))
        {
            status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, & tinfo->kthread, NULL);
            if (NT_SUCCESS(status))
            {
                ZwClose(threadHandle);
            }
            else
            {
                // may as well bugcheck
                DbgPrint("%s failed to get thread %d handle, status %08X\n", DbgPrefix, k, status);
            }
        }
        else
        {
            DbgPrint("%s failed to create thread %d, status %08X\n", DbgPrefix, k, status);
        }
    }

    /*
     * Create a symbolic link for user applications to interact with the driver
     */
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_NAME_STRING);
    status = IoCreateSymbolicLink(&symbolicLinkName, &ntDeviceName);
    if (! NT_SUCCESS(status))
    {
        UninitDevice(deviceObject);
        IoDeleteDevice(deviceObject);
        DbgPrint("%s IoCreateSymbolicLink returned 0x%x\n", DbgPrefix, status);
        return status;
    }

    /*
     * Establish userspace buffer access method
     */
    deviceObject->Flags |= DO_BUFFERED_IO;
    DbgPrint("%s <== DriverEntry\n", DbgPrefix);

    return status;
}

VOID
MyUnload(DRIVER_OBJECT* DriverObject)
{
    PDEVICE_OBJECT      deviceObject = DriverObject->DeviceObject;
    // PDEVICE_EXTENSION   deviceExtension = deviceObject->DeviceExtension;
    UNICODE_STRING      symbolicLinkName;

    DbgPrint("%s ==> Unload\n", DbgPrefix);

    // PAGED_CODE();

    /*
     * Delete the user-mode symbolic link and deviceobjct.
     */
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_NAME_STRING);
    IoDeleteSymbolicLink(&symbolicLinkName);

    /* uninit device extension */
    UninitDevice(deviceObject);

    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);

    /* let queued timer DPCs to complete */
    KeFlushQueuedDpcs();
    IoDeleteDevice(deviceObject);

    KeDeregisterBugCheckReasonCallback(& s_BugcheckReasonCallbackRecord);

    DbgPrint("%s <== Unload\n", DbgPrefix);
}

static VOID
UninitDevice(DEVICE_OBJECT* deviceObject)
{
    DEVICE_EXTENSION* deviceExtension = deviceObject->DeviceExtension;
    KIRQL irql;
    int   k;

    /* stop threads */
    DbgPrint("%s Stopping threads...\n", DbgPrefix);
    for (k = 0;  k < NTHREADS;  k++)
    {
        ThreadInfo* tinfo = & deviceExtension->threads[k];
        if (tinfo->kthread)
        {
            KeSetEvent(& tinfo->exitEvent, 0, FALSE);
            KeWaitForSingleObject(tinfo->kthread, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(tinfo->kthread);
            tinfo->kthread = NULL;
        }
    }

    /* stop timers */
    DbgPrint("%s Stopping timers...\n", DbgPrefix);
    for (k = 0;  k < NTIMERS;  k++)
    {
        TimerObject* timer = & deviceExtension->timers[k];

        /* 
         * KeCancelTimer does not wait for DPC procedure to complete, so there is
         * no danger of deadlock against currently running DPC procedure that also
         * acqures timerLock.
         */
        KeAcquireSpinLock(& timer->timerLock, & irql);
        timer->cancel = TRUE;
        KeCancelTimer(& timer->timer);
        KeReleaseSpinLock(& timer->timerLock, irql);

        /*
         * After this point KTIMER and KDPC are removed from the queue,
         * but DPC procedure may still be in progress and executing. It will no longer
         * re-queue KTIMER (because timer->cancel is set), but it may take a while before 
         * the current activation of DPC routine completes. It would be an error to deallocate 
         * KDPC or to unload the driver and remove DPC routine code from kernel space
         * before the DPC routine actually completes and DPC manager lets go of
         * KDPC block. Should call KeFlushQueuedDpcs to wait for its completion.
         */
    }

    if (deviceExtension->dataBuffer)
    {
        ExFreePoolWithTag(deviceExtension->dataBuffer, TAG);
        deviceExtension->dataBuffer = NULL;
        deviceExtension->dataSize = 0;
    }

    if (deviceExtension->dataLockInitialized)
    {
        ExDeleteResourceLite(& deviceExtension->dataLock);
        deviceExtension->dataLockInitialized = FALSE;
    }
}

NTSTATUS
MyDispatchCreate(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
    // PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status;
    // PFILE_CONTEXT       fileContext;

    UNREFERENCED_PARAMETER(DeviceObject);

    // PAGED_CODE();

    // irpStack = IoGetCurrentIrpStackLocation(Irp);

    status = STATUS_SUCCESS;

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return status;
}

NTSTATUS
MyDispatchClose(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
    // PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status;
    // PFILE_CONTEXT       fileContext;

    UNREFERENCED_PARAMETER(DeviceObject);

    // PAGED_CODE();

    // irpStack = IoGetCurrentIrpStackLocation(Irp);
    // ASSERT(irpStack->FileObject != NULL);    

    status = STATUS_SUCCESS;

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return status;
}

NTSTATUS
MyDispatchRead(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
    PDEVICE_EXTENSION   dvx = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION  irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS            status = STATUS_SUCCESS;
    ULONG_PTR           information = 0;
    SIZE_T              rqSize;
    uint64_t            rqOffset = largeInteger_to_uint64(& irpStack->Parameters.Read.ByteOffset);
    uint64_t            avlSize;

    C_ASSERT(sizeof(rqSize) >= sizeof(irpStack->Parameters.Read.Length));
    C_ASSERT(sizeof(rqSize) == sizeof(dvx->dataSize));

    DbgPrint("%s <== MyDispatchRead\n", DbgPrefix);

    // PFILE_CONTEXT       fileContext;
    // ASSERT(irpStack->FileObject != NULL);    
    // PAGED_CODE();


    /* zero bytes is a legitimate request */
    rqSize = irpStack->Parameters.Read.Length;
    if (rqSize != 0)
    {
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(& dvx->dataLock, TRUE);
        if (rqOffset >= (uint64_t) dvx->dataSize)
        {
            rqOffset = dvx->dataSize;
            rqSize = 0;
        }
        avlSize = (uint64_t) dvx->dataSize - rqOffset;
        if ((uint64_t) rqSize > avlSize)  rqSize = (SIZE_T) avlSize;
        if (rqSize)
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, dvx->dataBuffer + rqOffset, rqSize);
        ExReleaseResourceLite(& dvx->dataLock);
        status = STATUS_SUCCESS;
        information = rqSize;
        KeLeaveCriticalRegion();
    }

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = NT_SUCCESS(status) ? information : 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    DbgPrint("%s ==> MyDispatchRead\n", DbgPrefix);

    return status;
}

NTSTATUS
MyDispatchWrite(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
    PDEVICE_EXTENSION   dvx = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION  irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS            status = STATUS_SUCCESS;
    ULONG_PTR           information = 0;
    SIZE_T              rqSize, newSize;
    BYTE*               bp;

    C_ASSERT(sizeof(rqSize) == sizeof(newSize));
    C_ASSERT(sizeof(rqSize) == sizeof(dvx->dataSize));
    C_ASSERT(sizeof(rqSize) >= sizeof(irpStack->Parameters.Write.Length));

    DbgPrint("%s <== MyDispatchWrite\n", DbgPrefix);

    // PFILE_CONTEXT       fileContext;
    // ASSERT(irpStack->FileObject != NULL);    
    // PAGED_CODE();

    /* zero bytes is a legitimate request */
    rqSize = irpStack->Parameters.Write.Length;
    if (rqSize != 0)
    {
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(& dvx->dataLock, TRUE);
        newSize = rqSize + dvx->dataSize;
        if (newSize < rqSize)
        {
            status = STATUS_INVALID_PARAMETER;
        }
        else if (newSize > 10 * 1024 * 1024)
        {
            status = STATUS_FILE_TOO_LARGE;
        }
        /* 
         * tempting to allocate from PagedPool, but what if some other driver layers above us 
         * and calls IRP_MJ_WRITE at DISPATCH_LEVEL
         */
        else if (NULL == (bp = (BYTE*) ExAllocatePoolWithTag(NonPagedPool, newSize, TAG)))
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            if (dvx->dataSize)
                RtlCopyMemory(bp, dvx->dataBuffer, dvx->dataSize);
            RtlCopyMemory(bp + dvx->dataSize, Irp->AssociatedIrp.SystemBuffer, rqSize);
            if (dvx->dataBuffer)
                ExFreePoolWithTag(dvx->dataBuffer, TAG);
            dvx->dataBuffer = bp;
            dvx->dataSize = newSize;
            status = STATUS_SUCCESS;
            information = rqSize;
        }
        ExReleaseResourceLite(& dvx->dataLock);
        KeLeaveCriticalRegion();
    }

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = NT_SUCCESS(status) ? information : 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    DbgPrint("%s ==> MyDispatchWrite\n", DbgPrefix);

    return status;
}

NTSTATUS
MyDispatchIoControl(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
    PDEVICE_EXTENSION   dvx = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION  irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS            status = STATUS_SUCCESS;
    ULONG_PTR           information = 0;
    ULONG               rqSize = 0;
    VOID*               rqData = NULL;
    ULONG               maxSize = 1024;

    (void) dvx;    //  suppress "unused variable" diagnostic
        
    DbgPrint("%s ==> DispatchIoControl\n", DbgPrefix);

    // PFILE_CONTEXT       fileContext;
    // ASSERT(irpStack->FileObject != NULL);
    // fileContext = irpStack->FileObject->FsContext;    
    // status = IoAcquireRemoveLock(&fileContext->FileRundownLock, Irp);
    // if (! NT_SUCCESS(status))
    // {
    //     //
    //     // Lock is in a removed state. That means we have already received 
    //     // cleaned up request for this handle. 
    //     //
    //     Irp->IoStatus.Status = status;
    //     IoCompleteRequest(Irp, IO_NO_INCREMENT);
    //     return status;
    // }
    
    KeEnterCriticalRegion();

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_MYTEST_PRINT:
        rqSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
        rqData = copyin_alloc(irpStack->Parameters.DeviceIoControl.Type3InputBuffer, rqSize, sizeof(BYTE), 0, maxSize, Irp->RequestorMode, & status);
        if (rqData)
        {
            ((char*) rqData)[rqSize] = 0;
            DbgPrint("%s print:[%s]\n", DbgPrefix, (char*) rqData);
        }
        break;

    case IOCTL_MYTEST_LOG:
        rqSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
        rqData = copyin_alloc(irpStack->Parameters.DeviceIoControl.Type3InputBuffer, rqSize, sizeof(BYTE), 0, maxSize, Irp->RequestorMode, & status);
        if (rqData)
        {
            ((char*) rqData)[rqSize] = 0;
            status = logSystemMessage((const char*) rqData);
        }
        break;

        /*
         * Dump file can be examined in WinDbg using the following commands:
         *
         *     .enumtag
         *     !bugdump [component-name]
         *     !errlog
         *
         * Of these three, .enumtag is most reliable.
         *
         * !bugdump sometimes may fail to display valid crash data.
         *
         * !errlog may fail to display a pending packet.
         *
         */
    case IOCTL_MYTEST_PANIC:
        // note: must allocate on a page-aligned boundary (for XP and Server 2003), so requesting at least PAGE_SIZE
        rqSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
        rqData = copyin_alloc(irpStack->Parameters.DeviceIoControl.Type3InputBuffer, rqSize, sizeof(BYTE), PAGE_SIZE, maxSize, Irp->RequestorMode, & status);
        if (rqData)
        {
            ((char*) rqData)[rqSize] = 0;

            // Most likely system won't have sufficient time to flush the message to the event log,
            // but in this case it will be viewable with debugger "!errlog" command in the dump file
            logSystemMessage((const char*) rqData);

            if (KdRefreshDebuggerNotPresent() == FALSE)
            {
                // A kernel debugger is active
                DbgPrint("%s panic: %s\n", DbgPrefix, (char*) rqData);
                DbgBreakPoint();
            }
            else
            {
                // No kernel debugger attached, or kernel debugging not enabled
                s_panic_string = (char*) rqData;
                s_panic_strlen = rqSize;
                KeBugCheck(FILE_SYSTEM);
            }
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    if (rqData)
        ExFreePoolWithTag(rqData, TAG);

    KeLeaveCriticalRegion();

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = information;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    DbgPrint("%s <== MyDispatchIoControl\n", DbgPrefix);

    return status;
}

static VOID 
TimerRoutine(KDPC* Dpc, VOID* DeferredContext, VOID* SystemArgument1, VOID* SystemArgument2)
{
    TimerObject* timer = (TimerObject*) DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    DbgPrint("%s timer %d\n", DbgPrefix, (int) timer->context1);

    KeAcquireSpinLockAtDpcLevel(& timer->timerLock);
    if (! timer->cancel)
        KeSetTimer(& timer->timer, longToLargeInteger(-8 * UNITS_100NS_PER_SEC), & timer->timerDpc);
    KeReleaseSpinLockFromDpcLevel(& timer->timerLock);
}

static VOID 
ThreadMain(PVOID StartContext)
{
    ThreadInfo* tinfo = (ThreadInfo*) StartContext;
    int         tindex = (int) tinfo->context1;
    LONG        oldincr;

    // Windows 7 default for system threads is 8 (NORMAL_PRIORITY_CLASS, THREAD_PRIORITY_NORMAL)
    // can range from THREAD_PRIORITY_IDLE (1) to THREAD_PRIORITY_TIME_CRITICAL (15)
    DbgPrint("%s thread %d, prio: %d\n", DbgPrefix, tindex, (int) KeQueryPriorityThread(KeGetCurrentThread()));

    // add 2 to base prio
    // note that oldincr is an old increment over the base class priority
    // see http://msdn.microsoft.com/en-us/library/windows/desktop/ms685100%28v=VS.85%29.aspx
    oldincr = KeSetBasePriorityThread(KeGetCurrentThread(), 2);

    DbgPrint("%s thread %d, prio: %d -> %d\n", DbgPrefix, tindex, oldincr, (int) KeQueryPriorityThread(KeGetCurrentThread()));

    for (;;)
    {
        LARGE_INTEGER timeout = longToLargeInteger(-8 * UNITS_100NS_PER_SEC);
        NTSTATUS status = KeWaitForSingleObject(& tinfo->exitEvent, Executive, KernelMode, FALSE, & timeout);

        if (status == STATUS_TIMEOUT)
        {
            DbgPrint("%s thread %d\n", DbgPrefix, tindex);
        }
        else if (! NT_SUCCESS(status))
        {
            DbgPrint("%s thread %d aborting, status %08X\n", DbgPrefix, tindex, status);
            PsTerminateSystemThread(status);
        }
        else
        {
            DbgPrint("%s thread %d exiting\n", DbgPrefix, tindex);
            PsTerminateSystemThread(STATUS_SUCCESS);
        }
    }
}

static VOID
ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    /* 
     * On thread termination, this handler is called *before* cancelling IRPs.
     * The latter is done by IoCancelIrp for each IRP, already *after* calling this handler.
     * I.e. there still may be driver calls performed in the context of the thread *after* calling this handler.
     */

    PETHREAD ethread = NULL;

    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);

    PsLookupThreadByThreadId(ThreadId, & ethread);

    if (Create)
    {
        // DbgPrint("%s thread is being created\n", DbgPrefix);
    }
    else
    {
        // DbgPrint("%s thread is being terminated\n", DbgPrefix);
    }

    if (ethread)
        ObDereferenceObject(ethread);
}

static VOID*
copyin_alloc(const VOID* va, ULONG size, ULONG extraSize, ULONG minSize, ULONG maxSize, KPROCESSOR_MODE RequestorMode, NTSTATUS* pstatus)
{
    VOID* bp;
    BOOLEAN failed = FALSE;

    *pstatus = STATUS_SUCCESS;

    if (size + extraSize < size || size + extraSize > maxSize)
    {
        *pstatus = STATUS_INVALID_PARAMETER;
        return NULL;
    }

    bp = ExAllocatePoolWithTag(NonPagedPool, max(minSize, size + extraSize), TAG);
    if (bp == NULL)
    {
        *pstatus = STATUS_INSUFFICIENT_RESOURCES;
        return NULL;
    }

    if (RequestorMode == KernelMode)
    {
        RtlCopyMemory(bp, va, size);
    }
    else
    {
        try
        {
            ProbeForRead((void*) va, size, sizeof(BYTE));
            RtlCopyMemory(bp, va, size);
        }
        except (EXCEPTION_EXECUTE_HANDLER)
        {
            *pstatus = GetExceptionCode();
            failed = TRUE;
        }
    }

    if (failed)
    {
        ExFreePoolWithTag(bp, TAG);
        bp = NULL;
    }

    return bp;
}

__drv_maxIRQL(DISPATCH_LEVEL)
static NTSTATUS 
logSystemMessage(const char* messageText)
{
    /* 
     * Error log packet consists of:
     *   - standard header (IO_ERROR_LOG_PACKET)
     *   - DumpData: array of driver-defined ULONGs (which we do not use here)
     *   - array of nul-terminated Unicode insertion strings
     *
     * PacketSize = sizeof(IO_ERROR_LOG_PACKET) + sizeof(ULONG) * (DumpDataCount - 1) + size of insertion strings
     *
     * Total cannot exceed ERROR_LOG_MAXIMUM_SIZE.
     */

    IO_ERROR_LOG_PACKET* logEntry = NULL;
    WCHAR* wp;
    size_t maxchars = (ERROR_LOG_MAXIMUM_SIZE - sizeof(IO_ERROR_LOG_PACKET)) / sizeof(wchar_t) - 1;
    size_t len = strlen(messageText);
    size_t k;

    if (len > maxchars)  len = maxchars;

    logEntry = IoAllocateErrorLogEntry(s_DriverObject, (UCHAR) (sizeof(IO_ERROR_LOG_PACKET) + (len + 1) * sizeof(WCHAR)));
    if (logEntry == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    //logEntry->MajorFunctionCode = 0;
    logEntry->RetryCount = 0;
    logEntry->DumpDataSize = 0;
    logEntry->NumberOfStrings = 1;
    logEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET);
    logEntry->ErrorCode = MYTEST_INFORMATIONAL_TEXTMESSAGE;
    // logEntry->EventCategory = 0;
    // logEntry->UniqueErrorValue = ...;
    // logEntry->FinalStatus = 0;
    // logEntry->SequenceNumber = 0;
    // logEntry->IoControlCode = 0;
    // logEntry->DeviceOffset = ...;
    // logEntry->DumpData[0] = 0;

    /* copy insertion string */
    wp = (WCHAR*) ((BYTE*) logEntry + sizeof(IO_ERROR_LOG_PACKET));
    for (k = 0;  k < len;  k++)
        *wp++ = 0xFF & (WCHAR) *messageText++;
    *wp = 0;

    IoWriteErrorLogEntry(logEntry);

    return STATUS_SUCCESS;
}

/* available since Windows XP SP1 and Windows Server 2003 */
__drv_requiresIRQL(HIGH_LEVEL)
static VOID 
BugCheckSecondaryDumpDataCallback(
    __in    KBUGCHECK_CALLBACK_REASON Reason,
    __in    struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record,
    __inout PVOID ReasonSpecificData,            // pointer to KBUGCHECK_SECONDARY_DUMP_DATA
    __in    ULONG ReasonSpecificDataLength)      // always sizeof(KBUGCHECK_SECONDARY_DUMP_DATA)
{
    KBUGCHECK_SECONDARY_DUMP_DATA* data = (KBUGCHECK_SECONDARY_DUMP_DATA*) ReasonSpecificData;

    UNREFERENCED_PARAMETER(Record);

    if (Reason == KbCallbackSecondaryDumpData && 
        data != NULL && 
        ReasonSpecificDataLength >= sizeof(KBUGCHECK_SECONDARY_DUMP_DATA))
    {
        ULONG datasize = min(data->MaximumAllowed, (ULONG) s_panic_strlen);

        data->Guid = COMPONENT_GUID;

        if (data->OutBuffer == NULL)
        {
            /* requesting size */
            if (data->InBufferLength >= datasize)
            {
                data->OutBuffer = data->InBuffer;
                data->OutBufferLength = datasize;
            }
            else
            {
                /*
                 * in Windows XP and Windows Server 2003 s_panic_string must begin
                 * on a page-aligned boundary in memory
                 */
                data->OutBuffer = (char*) s_panic_string;
                data->OutBufferLength = datasize;
            }
        }
        else if (data->InBuffer && data->InBuffer == data->OutBuffer)
        {
            /* requesting actual data */
            RtlCopyMemory(data->OutBuffer, s_panic_string, datasize);
            data->OutBufferLength = datasize;
        }
    }
}
