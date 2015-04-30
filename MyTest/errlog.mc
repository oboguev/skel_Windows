;/*++ BUILD Version: 0001    // Increment this if a change has global effects
;
;Module Name:
;
;    errlog.mc
;
;Abstract:
;
;    Constant definitions for the I/O error code log values.
;
;Revision History:
;
;--*/
;
;#ifndef __ERRLOGLOG_MC__
;#define __ERRLOGLOG_MC__
;
;//
;//  Status values are 32 bit values layed out as follows:
;//
;//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
;//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
;//  +---+-+-------------------------+-------------------------------+
;//  |Sev|C|       Facility          |               Code            |
;//  +---+-+-------------------------+-------------------------------+
;//
;//  where
;//
;//      Sev - is the severity code
;//
;//          00 - Success
;//          01 - Informational
;//          10 - Warning
;//          11 - Error
;//
;//      C - is the Customer code flag
;//
;//      Facility - is the facility code
;//
;//      Code - is the facility's status code
;//
;
MessageIdTypedef=NTSTATUS

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

FacilityNames=(System=0x0
               RpcRuntime=0x2:FACILITY_RPC_RUNTIME
               RpcStubs=0x3:FACILITY_RPC_STUBS
               Io=0x4:FACILITY_IO_ERROR_CODE
               MyTest=0x7:FACILITY_MYTEST
              )


MessageId=0x0001 Facility=MyTest Severity=Success SymbolicName=MYTEST_SUCCESS_TEXTMESSAGE
Language=English
%2
.

MessageId=0x0002 Facility=MyTest Severity=Informational SymbolicName=MYTEST_INFORMATIONAL_TEXTMESSAGE
Language=English
%2
.

MessageId=0x0003 Facility=MyTest Severity=Warning SymbolicName=MYTEST_WARNING_TEXTMESSAGE
Language=English
%2
.

MessageId=0x0004 Facility=MyTest Severity=Error SymbolicName=MYTEST_ERROR_TEXTMESSAGE
Language=English
%2
.

;#endif /* __ERRLOGLOG_MC__ */

