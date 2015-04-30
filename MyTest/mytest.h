#ifndef __MYTEST_H__
#define __MYTEST_H__

#define NTDEVICE_NAME_STRING      L"\\Device\\MyTestDevice"
#define SYMBOLIC_NAME_STRING      L"\\DosDevices\\MyTestDevice"
#define TAG ((ULONG)'eTyM')

#define DbgPrefix "MYTEST.SYS: "
#define DbgPrintPrefix DbgPrint(DbgPrefix)

// warning C4127: conditional expression is constant
#pragma warning( disable : 4127 )

#if DBG
#  define DebugPrint(_x_)  do { DbgPrintPrefix; DbgPrint _x_; } while (0)
#else
#  define DebugPrint(_x_)
#endif

#  define Print(_x_)  do { DbgPrintPrefix; DbgPrint _x_; } while (0)

typedef unsigned __int64 uint64_t;
typedef unsigned char BYTE;

#define NTIMERS  4
#define NTHREADS  4

typedef struct
{
    KTIMER         timer;
    KSPIN_LOCK     timerLock;
    KDPC           timerDpc;
    BOOLEAN        cancel;
    ULONG_PTR      context1;
    ULONG_PTR      context2;
}
TimerObject;

typedef struct
{
    PKTHREAD       kthread;
    KEVENT         exitEvent;
    ULONG_PTR      context1;
    ULONG_PTR      context2;
}
ThreadInfo;

typedef struct _DEVICE_EXTENSION 
{
    DEVICE_OBJECT* deviceObject;
    TimerObject    timers[NTIMERS];
    ThreadInfo     threads[NTHREADS];
    BYTE*          dataBuffer;
    SIZE_T         dataSize;
    ERESOURCE      dataLock;
    BOOLEAN        dataLockInitialized;
} 
DEVICE_EXTENSION, *PDEVICE_EXTENSION;

DRIVER_INITIALIZE DriverEntry;

DRIVER_UNLOAD MyUnload;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH MyDispatchCreate;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH MyDispatchClose;

__drv_dispatchType(IRP_MJ_READ)
DRIVER_DISPATCH MyDispatchRead;

__drv_dispatchType(IRP_MJ_WRITE)
DRIVER_DISPATCH MyDispatchWrite;

// __drv_dispatchType(IRP_MJ_CLEANUP)
// DRIVER_DISPATCH MyDispatchCleanup;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH MyDispatchIoControl;

// DRIVER_CANCEL MyCancelRoutine;
// KDEFERRED_ROUTINE CustomTimerDPC;

#endif // __MYTEST_H__

