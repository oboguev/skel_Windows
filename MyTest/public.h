#ifndef __MYTESTDEV_PUBLIC_H__
#define __MYTESTDEV_PUBLIC_H__

/*
 * Defintiona common to applications and driver
 */

#ifndef CTL_CODE
#  include "devioctl.h"
#endif

#define IOCTL_MYTEST_PRINT       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_WRITE_ACCESS)
#define IOCTL_MYTEST_LOG         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_WRITE_ACCESS)
#define IOCTL_MYTEST_PANIC       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_WRITE_ACCESS)

#define COMPONENT_NAME     "MyTest"
//#define COMPONENT_NAME_UC  L"MyTest"
#define DEVICE_NAME        "MyTestDevice"

#ifndef FACILITY_MYTEST
#  define FACILITY_MYTEST                  0x7
#endif

#endif // __MYTESTDEV_PUBLIC_H__

