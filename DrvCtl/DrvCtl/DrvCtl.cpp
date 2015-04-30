#include "stdafx.h"

#define countof(a)  (sizeof(a) / sizeof((a)[0]))
#define _teq(s1, s2)  (0 == _tcscmp((s1), (s2)))

static int do_install(const TCHAR* drvname, const TCHAR* drvfile);
static int do_uninstall(const TCHAR* drvname);
static int do_start(const TCHAR* drvname);
static int do_stop(const TCHAR* drvname);
static int do_ioctl(DWORD code, char* text);
static int do_write(char* text1, char* text2);
static int do_read();
static int do_mapdos(TCHAR* dosname);
static int do_unmapdos(TCHAR* dosname);
static int do_register(const TCHAR* drvname, const TCHAR* drvfile);
static int do_unregister(const TCHAR* drvname);
static void usage();
static const TCHAR* match_verb(const TCHAR* s);
static BOOL check_match_verb(const TCHAR* verb, const TCHAR* s);
static void open_service_manager();
static void verify_driver_is_installed(const TCHAR* drvname);
static void verify_driver_is_not_installed(const TCHAR* drvname);
static BOOL is_driver_installed(const TCHAR* drvname);
static void open_device();
static void close_device();
static const TCHAR* validate_drivername_syntax(const TCHAR* drvname);
static void windows_error(const TCHAR* message, DWORD dwError);
static void fatal_windows_error(const TCHAR* message, DWORD dwError);
static TCHAR* dupstr(const TCHAR* s);
static TCHAR lastchar(const TCHAR* s);
static const TCHAR* unquote(const TCHAR* s);
static TCHAR* collect_text(TCHAR* args[], int start, int argc);
static TCHAR* concat(const TCHAR* s1, const TCHAR* s2);
#ifndef UNICODE
#  define t2a(text)  text
#else
static char* t2a(const TCHAR* text);
#endif

#define CHECK_STATUS_SUCCESS(expr)  do { if (ERROR_SUCCESS != (status = (expr)))  goto cleanup_status; } while (0)

static const TCHAR* verbs[] = { _T("install"), _T("uninstall"), _T("deinstall"), _T("start"), _T("stop"),
                                _T("write"), _T("read"), _T("mapdos"), _T("unmapdos"), _T("print"), _T("log"), _T("panic") };

static SC_HANDLE sc_manager = NULL;
static SC_HANDLE driver_service = NULL;
static HANDLE h_device = NULL;

static const TCHAR* device_name = TEXT("\\\\.\\") TEXT(DEVICE_NAME);

int _tmain(int argc, _TCHAR* argv[])
{
    const TCHAR* drvname = NULL;

    if (argc < 2)
        usage();

    const TCHAR* verb = match_verb(argv[1]);
    if (verb == NULL)
        usage();

    if (_teq(verb, _T("install")))
    {
        if (argc != 3 && argc != 4)
            usage();
        drvname = argv[2];
        drvname = validate_drivername_syntax(drvname);
        return do_install(drvname, argc == 4 ? argv[3] : NULL);
    }
    else if (_teq(verb, _T("uninstall")) || _teq(verb, _T("deinstall")))
    {
        if (argc != 3)
            usage();
        drvname = argv[2];
        drvname = validate_drivername_syntax(drvname);
        return do_uninstall(drvname);
    }
    else if (_teq(verb, _T("start")))
    {
        if (argc != 3)
            usage();
        drvname = argv[2];
        drvname = validate_drivername_syntax(drvname);
        return do_start(drvname);
    }
    else if (_teq(verb, _T("stop")))
    {
        if (argc != 3)
            usage();
        drvname = argv[2];
        drvname = validate_drivername_syntax(drvname);
        return do_stop(drvname);
    }
    else if (_teq(verb, _T("mapdos")))
    {
        if (argc != 3)
            usage();
        return do_mapdos(argv[2]);
    }
    else if (_teq(verb, _T("unmapdos")))
    {
        if (argc != 3)
            usage();
        return do_unmapdos(argv[2]);
    }
    else if (_teq(verb, _T("write")))
    {
        if (argc < 3)
            usage();
        char* text = t2a(collect_text(argv, 2, argc));
        open_device();
        int status = do_write(text, "\r\n");
        close_device();
        return status;
    }
    else if (_teq(verb, _T("read")))
    {
        if (argc != 2)
            usage();
        open_device();
        int status = do_read();
        close_device();
        return status;
    }
    else if (_teq(verb, _T("print")))
    {
        if (argc < 3)
            usage();
        char* text = t2a(collect_text(argv, 2, argc));
        open_device();
        int status = do_ioctl(IOCTL_MYTEST_PRINT, text);
        close_device();
        return status;
    }
    else if (_teq(verb, _T("log")))
    {
        if (argc < 3)
            usage();
        char* text = t2a(collect_text(argv, 2, argc));
        open_device();
        int status = do_ioctl(IOCTL_MYTEST_LOG, text);
        close_device();
        return status;
    }
    else if (_teq(verb, _T("panic")))
    {
        if (argc < 3)
            usage();
        char* text = t2a(collect_text(argv, 2, argc));
        open_device();
        int status = do_ioctl(IOCTL_MYTEST_PANIC, text);
        close_device();
        return status;
    }
    else
    {
        usage();
    }

    return 0;
}

static int do_install(const TCHAR* drvname, const TCHAR* drvfile)
{
    DWORD dwServiceType = SERVICE_KERNEL_DRIVER;
    // DWORD dwServiceType = SERVICE_FILE_SYSTEM_DRIVER;
    // DWORD dwServiceType = SERVICE_RECOGNIZER_DRIVER;

    if (drvfile == NULL)
    {
        TCHAR* p = (TCHAR*) malloc(sizeof(TCHAR) * (_tcslen(drvname) + 4 + 1));
        if (p == NULL)
        {
            _ftprintf(stderr, _T("Error: Out of memory.\n"));
            exit(ERROR_NOT_ENOUGH_MEMORY);
        }
        _tcscpy(p, drvname);
        _tcscat(p, TEXT(".sys"));
        drvfile = p;
    }
    else
    {
        drvfile = unquote(drvfile);
    }

    TCHAR dpath[_MAX_PATH + 2];

    DWORD dw = GetFullPathName(drvfile, _MAX_PATH, dpath, NULL);
    if (dw == 0)
    {
        // _ftprintf(stderr, TEXT("Driver file: [%s]\n"), drvfile);
        fatal_windows_error(_T("Unable to locate driver file"), GetLastError());
    }
    if (dw >= _MAX_PATH)
    {
        _ftprintf(stderr, _T("Error: Driver file path is too long.\n"));
        exit(ERROR_BAD_ARGUMENTS);
    }

    if (GetFileAttributes(dpath) == INVALID_FILE_ATTRIBUTES)
        fatal_windows_error(_T("Unable to access driver file"), GetLastError());

    if (_tcschr(dpath, ' '))
    {
        MoveMemory(dpath + 1, dpath, sizeof(TCHAR) * (_tcslen(dpath) + 1));
        dpath[0] = '\"';
        _tcscat(dpath, TEXT("\""));
    }

    open_service_manager();
    verify_driver_is_not_installed(drvname);

    driver_service = CreateService(sc_manager, drvname, NULL, SC_MANAGER_ALL_ACCESS, dwServiceType,
                                   SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, 
                                   dpath, NULL, NULL, NULL, NULL, NULL);

    if (driver_service == NULL)
        fatal_windows_error(_T("Unable to create driver service"), GetLastError());

    drvfile = dpath;
    if (*drvfile == '"')
        drvfile++;
    if (lastchar(dpath + 1) == '"')
        dpath[_tcslen(dpath) - 1] = 0;

    return do_register(drvname, drvfile);
}

static int do_register(const TCHAR* drvname, const TCHAR* drvfile)
{
    int status = do_unregister(drvname);
    if (status != ERROR_SUCCESS)
        return status;

    LPCTSTR keyname = concat(TEXT("SYSTEM\\CurrentControlSet\\Services\\EventLog\\System\\"), drvname);
    HKEY hKey = NULL;

    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, & hKey); 
    if (status == ERROR_SUCCESS)
        return ERROR_SUCCESS;

    DWORD typesSupported = FACILITY_MYTEST;

    CHECK_STATUS_SUCCESS(RegCreateKeyEx(HKEY_LOCAL_MACHINE, keyname, 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, & hKey, NULL));
    CHECK_STATUS_SUCCESS(RegSetValueEx(hKey, TEXT("EventMessageFile"), NULL, REG_EXPAND_SZ, (BYTE*) drvfile, sizeof(TCHAR) * (_tcslen(drvfile) + 1)));
    CHECK_STATUS_SUCCESS(RegSetValueEx(hKey, TEXT("TypesSupported"), NULL, REG_DWORD, (BYTE*) & typesSupported, sizeof(DWORD)));
    CHECK_STATUS_SUCCESS(RegFlushKey(hKey));
    CHECK_STATUS_SUCCESS(RegCloseKey(hKey));

    return ERROR_SUCCESS;

cleanup_status:

    if (status != ERROR_SUCCESS)
        fatal_windows_error(_T("Unable to register driver as event message source"), status);

    return status;
}

static int do_uninstall(const TCHAR* drvname)
{
    if (is_driver_installed(drvname))
    {
        int ex = do_stop(drvname);
        if (ex != 0)  return ex;

        if (! DeleteService(driver_service))
            fatal_windows_error(_T("Unable to delete driver service"), GetLastError());
    }

    return do_unregister(drvname);
}

static int do_unregister(const TCHAR* drvname)
{
    LPCTSTR keyname = concat(TEXT("SYSTEM\\CurrentControlSet\\Services\\EventLog\\System\\"), drvname);
    HKEY hKey = NULL;
    LONG status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, & hKey); 
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        return ERROR_SUCCESS;

    CHECK_STATUS_SUCCESS(status);
    CHECK_STATUS_SUCCESS(RegDeleteTree(hKey, NULL));
    CHECK_STATUS_SUCCESS(RegDeleteKeyEx(HKEY_LOCAL_MACHINE, keyname, KEY_WOW64_64KEY, NULL));

    return status;

cleanup_status:

    if (status != ERROR_SUCCESS)
        fatal_windows_error(_T("Unable to unregister driver as event log message source"), status);

    return status;
}

static int do_start(const TCHAR* drvname)
{
    SERVICE_STATUS status;

    verify_driver_is_installed(drvname);

    if (! QueryServiceStatus(driver_service, & status))
        fatal_windows_error(_T("Unable to access driver service"), GetLastError());

    if (status.dwCurrentState == SERVICE_RUNNING)
        return 0;

    if (! StartService(driver_service, 0, NULL))
        fatal_windows_error(_T("Unable to start driver service"), GetLastError());

    DWORD dwTime0 = GetTickCount();
    BOOL printed = FALSE;

    for (;;)
    {
        if (! QueryServiceStatus(driver_service, & status))
            fatal_windows_error(_T("Unable to access driver service"), GetLastError());

        if (status.dwCurrentState == SERVICE_RUNNING)
            break;

        if (! printed && (GetTickCount() - dwTime0 > 1000))
        {
            _tprintf(_T("Starting driver ...\n"));
            printed = TRUE;
        }

        Sleep(100);
    }

    if (printed)
        _tprintf(_T("Started driver.\n"));

    return 0;
}

static int do_stop(const TCHAR* drvname)
{
    SERVICE_STATUS status;

    verify_driver_is_installed(drvname);

    if (! QueryServiceStatus(driver_service, & status))
        fatal_windows_error(_T("Unable to access driver service"), GetLastError());

    if (status.dwCurrentState == SERVICE_STOPPED)
        return 0;

    if (! ControlService(driver_service, SERVICE_CONTROL_STOP, & status))
    {
        DWORD dwError = GetLastError();
        if (dwError != ERROR_SERVICE_NOT_ACTIVE)
        {
            fatal_windows_error(_T("Unable to stop driver service"), dwError);
        }
    }

    DWORD dwTime0 = GetTickCount();
    BOOL printed = FALSE;

    for (;;)
    {
        if (! QueryServiceStatus(driver_service, & status))
            fatal_windows_error(_T("Unable to access driver service"), GetLastError());

        if (status.dwCurrentState == SERVICE_STOPPED)
            break;

        if (! printed && (GetTickCount() - dwTime0 > 1000))
        {
            _tprintf(_T("Stopping driver ...\n"));
            printed = TRUE;
        }

        Sleep(100);
    }

    if (printed)
        _tprintf(_T("Stopped driver.\n"));

    return 0;
}

static int do_mapdos(TCHAR* dosname)
{
    if (_tcslen(dosname) == 0)
        usage();

    if (_tcslen(dosname) == 2 && dosname[1] == ':')
    {
        _tprintf(_T("For safety reasons, redefinition of drive names is not permitted.\n"));
        exit(2);
    }

    const TCHAR* target = TEXT("\\Device\\") TEXT(DEVICE_NAME);

    if (DefineDosDevice(DDD_RAW_TARGET_PATH, dosname, target))
    {
        _tprintf(_T("Defined %s -> %s\n"), dosname, target);
        return ERROR_SUCCESS;
    }
    else
    {
        DWORD dwError = GetLastError();
        _tprintf(_T("Unable to map %s -> %s\n"), dosname, target);
        windows_error(_T("Error"), dwError);
        return dwError;
    }
}

static int do_unmapdos(TCHAR* dosname)
{
    if (_tcslen(dosname) == 0)
        usage();

    if (_tcslen(dosname) == 2 && dosname[1] == ':')
    {
        _tprintf(_T("For safety reasons, redefinition of drive names is not permitted.\n"));
        exit(2);
    }

    const TCHAR* target = TEXT("\\Device\\") TEXT(DEVICE_NAME);

    if (DefineDosDevice(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH, dosname, target))
    {
        _tprintf(_T("Undefined %s -> %s\n"), dosname, target);
        return ERROR_SUCCESS;
    }
    else
    {
        DWORD dwError = GetLastError();
        _tprintf(_T("Unable to unmap %s -> %s\n"), dosname, target);
        windows_error(_T("Error"), dwError);
        return dwError;
    }
}

static int do_write(char* text1, char* text2)
{
    char* text = text1;

    if (text2 && *text2)
    {
        int len = strlen(text1) + strlen(text2);
        text = (char*) malloc(len + 1);
        if (text == NULL)
        {
            _ftprintf(stderr, _T("Error: Out of memory.\n"));
            exit(ERROR_NOT_ENOUGH_MEMORY);
        }
        strcpy(text, text1);
        strcat(text, text2);
    }

    DWORD wrsize = 0;
    if (WriteFile(h_device, text, strlen(text), & wrsize, NULL))
    {
        if (wrsize != strlen(text))
            _ftprintf(stderr, _T("Partial write: %d out of %d bytes\n"), (int) wrsize, (int) strlen(text));
        return ERROR_SUCCESS;
    }
    else
    {
        DWORD dwError = GetLastError();
        windows_error(_T("Unable to write to device"), dwError);
        return dwError;
    }
}

static int do_read()
{
    char buffer[64 + 1];
    LONG fpos = 0;

    for (;;)
    {
        SetFilePointer(h_device, fpos, NULL, FILE_BEGIN);

        DWORD rdsize = 0;
        if (! ReadFile(h_device, buffer, 64, & rdsize, NULL))
        {
            DWORD dwError = GetLastError();
            windows_error(_T("Unable to write to device"), dwError);
            return dwError;
        }

        if (rdsize == 0)
            return ERROR_SUCCESS;

        buffer[rdsize] = 0;
        printf("%s", buffer);
        fpos += rdsize;
    }
}

static void open_service_manager()
{
    if (sc_manager == NULL)
    {
        sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (sc_manager == NULL)
            fatal_windows_error(_T("Unable to open service control manager"), GetLastError());
    }
}

static BOOL is_driver_installed(const TCHAR* drvname)
{
    if (driver_service != NULL)
        return TRUE;

    open_service_manager();
    driver_service = OpenService(sc_manager, drvname, SC_MANAGER_ALL_ACCESS);

    if (driver_service == NULL)
    {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            _tprintf(_T("Driver \"%s\" is not installed.\n"), drvname);
            return FALSE;
        }
        else
        {
            fatal_windows_error(_T("Unable to access driver service"), dwError);
        }
    }

    SERVICE_STATUS status;
    if (! QueryServiceStatus(driver_service, & status))
        fatal_windows_error(_T("Unable to access driver service"), GetLastError());

    if (status.dwServiceType != SERVICE_KERNEL_DRIVER && 
        status.dwServiceType != SERVICE_FILE_SYSTEM_DRIVER)
    {
        _ftprintf(stderr, _T("Service \"%s\" is not a driver.\n"), drvname);
        exit(ERROR_BAD_ARGUMENTS);
    }

    return TRUE;
}

static void verify_driver_is_installed(const TCHAR* drvname)
{
    if (! is_driver_installed(drvname))
        exit(ERROR_SERVICE_DOES_NOT_EXIST);
}

static void verify_driver_is_not_installed(const TCHAR* drvname)
{
    open_service_manager();
    SC_HANDLE h = OpenService(sc_manager, drvname, SC_MANAGER_ENUMERATE_SERVICE);
    if (h != NULL)
    {
        _ftprintf(stderr, _T("Driver \"%s\" is already installed.\n"), drvname);
        exit(ERROR_BAD_ARGUMENTS);
    }

    if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
    {
        fatal_windows_error(_T("Unable to access driver service"), GetLastError());
    }
}

static void open_device()
{
    if (h_device == NULL)
    {
        h_device = CreateFile(device_name, 
                              GENERIC_READ | GENERIC_WRITE, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE, 
                              NULL, 
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);

        if (h_device == INVALID_HANDLE_VALUE)
        {
            h_device = NULL;
            fatal_windows_error(_T("Unable to open the device"), GetLastError());
        }
    }
}

static void close_device()
{
    if (h_device != NULL)
    {
        CloseHandle(h_device);
        h_device = NULL;
    }
}

static int do_ioctl(DWORD code, char* text)
{
    DWORD bytesReturned = 0;

    if (! DeviceIoControl(h_device, code, text, strlen(text), NULL, 0, & bytesReturned, NULL))
    {
        DWORD dwError = GetLastError();
        windows_error(_T("Unable to perform ioctl function on the device"), dwError);
        return dwError;
    }
    else
    {
        return ERROR_SUCCESS;
    }
}

static void usage()
{
    fprintf(stderr, "usage:  drvctl install   mydrv [mydrv.sys]\n");
    fprintf(stderr, "        drvctl uninstall mydrv\n");
    fprintf(stderr, "        drvctl start     mydrv\n");
    fprintf(stderr, "        drvctl stop      mydrv\n");
    fprintf(stderr, "        drvctl mapdos    dosname\n");
    fprintf(stderr, "        drvctl unmapdos  dosname\n");
    fprintf(stderr, "        drvctl write     text ...\n");
    fprintf(stderr, "        drvctl read\n");
    fprintf(stderr, "        drvctl print     text ...\n");
    fprintf(stderr, "        drvctl log       text ...\n");
    fprintf(stderr, "        drvctl panic     text ...\n");
    exit(ERROR_BAD_ARGUMENTS);
}

static const TCHAR* match_verb(const TCHAR* s)
{
    const TCHAR* verb = NULL;

    for (int k = 0;  k < countof(verbs);  k++)
    {
        if (check_match_verb(verbs[k], s))
        {
            if (verb)
                return NULL;
            verb = verbs[k];
        }
    }

    return verb;
}

static BOOL check_match_verb(const TCHAR* verb, const TCHAR* s)
{
    for (;  *verb && *s;  verb++, s++)
    {
        if (_totupper(*verb) != _totupper(*s))
            return FALSE;
    }

    return ('\0' == *s);
}

static const TCHAR* validate_drivername_syntax(const TCHAR* drvname)
{
    BOOL bad = FALSE;

    drvname = unquote(drvname);

    if (*drvname == '\0')  bad = TRUE;

    for (const TCHAR* p = drvname; *p;  p++)
    {
        if (! _istalnum(*p))  bad = TRUE;
    }

    if (bad)
    {
        _ftprintf(stderr, _T("Error: \"%s\" is not a valid driver name.\n"), drvname);
        exit(ERROR_BAD_ARGUMENTS);
    }

    return drvname;
}

static void fatal_windows_error(const TCHAR* message, DWORD dwError)
{
    windows_error(message, dwError);
    exit(dwError);
}

static void windows_error(const TCHAR* message, DWORD dwError)
{
    if (message && *message)
        _ftprintf(stderr, _T("Error: %s.\n"), message);

    LPVOID lpMsgBuf = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf, 0, NULL);

    if (lpMsgBuf && *(LPTSTR)lpMsgBuf)
    {
        _ftprintf(stderr, _T("%s.\n"), (LPTSTR) lpMsgBuf);
    }
    else
    {
        _ftprintf(stderr, _T("Error code: %08X\n"), dwError);
    }

    if (lpMsgBuf)
        LocalFree(lpMsgBuf);
}

static TCHAR* dupstr(const TCHAR* s)
{
    int len = _tcslen(s);
    TCHAR* p = (TCHAR*) malloc(sizeof(TCHAR) * (len + 1));
    if (p == NULL)
    {
        _ftprintf(stderr, _T("Error: Out of memory.\n"));
        exit(ERROR_NOT_ENOUGH_MEMORY);
    }
    _tcscpy(p, s);
    return p;
}

static TCHAR lastchar(const TCHAR* s)
{
    int len = _tcslen(s);
    return len ? s[len - 1] : '\0';
}

static const TCHAR* unquote(const TCHAR* s)
{
    if (*s == '"' && lastchar(s) == '"' ||
        *s == '\'' && lastchar(s) == '\'')
    {
        TCHAR* p = dupstr(s);
        int len = _tcslen(p);
        p[len - 1] = '\0';
        return p + 1;
    }
    else
    {
        return s;
    }
}

static TCHAR* collect_text(TCHAR* args[], int start, int argc)
{
    int len = 0;
    int pos;
    TCHAR* bp;

    for (pos = start;  pos < argc;  pos++)
    {
        if (pos != start)
            len++;
        len += _tcslen(args[pos]);
    }

    bp = (TCHAR*) malloc((len + 1) * sizeof(TCHAR));
    if (bp == NULL)
    {
        _ftprintf(stderr, _T("Error: Out of memory.\n"));
        exit(ERROR_NOT_ENOUGH_MEMORY);
    }
    bp[0] = 0;

    for (pos = start;  pos < argc;  pos++)
    {
        if (pos != start)
            _tcscat(bp, TEXT(" "));
        _tcscat(bp, args[pos]);
    }

    return bp;
}

#ifdef UNICODE
static char* t2a(const TCHAR* text)
{
    int len = _tcslen(text);
    size_t rqlen = wcstombs(NULL, text, 3 * len + 10);
    char* bp = (char*) malloc(rqlen + 1);
    size_t cvlen = wcstombs(bp, text, rqlen);
    bp[min(cvlen, rqlen)] = 0;
    return bp;
}
#endif

static TCHAR* concat(const TCHAR* s1, const TCHAR* s2)
{
    int len = _tcslen(s1) + _tcslen(s2);
    TCHAR* p = (TCHAR*) malloc(sizeof(TCHAR) * (len + 1));
    if (p == NULL)
    {
        _ftprintf(stderr, _T("Error: Out of memory.\n"));
        exit(ERROR_NOT_ENOUGH_MEMORY);
    }
    _tcscpy(p, s1);
    _tcscat(p, s2);
    return p;
}
