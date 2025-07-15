+++
title = 'Bininst1/Bininst2' 
date = '2025-03-07' 
authors = ["Abizer"]
+++

## Bininst1:

We are given a .exe that seems to throw errors we just want to find flag this is doable with just a decompiler but it would be a whole lot harder to do.

First frida allows us to intercept any function that we want so if we just intercept any syscalls made to nt.dll or kernel32.dll we can see almost all functions that are called.

This is the script i used in python i will just be putting the js part from now on so that there is less clutter:

```python
import frida
import sys


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


def main():
    target_binary = "./bininst1/bininst1.exe"
    try:
        pid = frida.spawn([target_binary])
        session = frida.attach(pid)
    except frida.ProcessNotFoundError:
        print(f"Error: Binary '{target_binary}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error spawning or attaching to process: {e}")
        sys.exit(1)

    script_code = """
    The js part here
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    frida.resume(pid)

    print("[*] Frida is running. Press Ctrl+C to exit.")
    sys.stdin.read()

    session.detach()


if __name__ == '__main__':
    main()
```

But the binary gives us a hint to what is happening so we want to look for functions like sleep or settimeout:

```JavaScript
// Hook NtDelayExecution
Interceptor.attach(Module.getExportByName("ntdll.dll", "NtDelayExecution"), {
    onEnter(args) {
        const alertable = args[^0].toInt32();
        const intervalPtr = args[^1];
        const interval = intervalPtr.readInt64();  // in 100ns units

        console.log(`[NtDelayExecution] Alertable: ${alertable}, Interval: ${interval} (100ns units)`);
    }
});

// Hook Sleep
Interceptor.attach(Module.getExportByName("kernel32.dll", "Sleep"), {
    onEnter(args) {
        console.log(`[Sleep] Duration: ${args[^0].toInt32()} ms`);
    }
});
```

This gives the following output:

```
[*] Frida is running. Press Ctrl+C to exit.
Hi, I have the flag for you just right here!
I'll just take a quick nap before I print it out for you, should only take me a decade or so!
zzzzzzzz....
[Sleep] Duration: -2 ms
```

Sleep -2 ms is invalid but it will actually wrap around to 4294967294 about 49 days if we replace this call with something else we should have flag.
Actually we dont need to replace it with any function at all:

```JavaScript
Interceptor.replace(Module.getExportByName("kernel32.dll", "Sleep"), new NativeCallback(function(ms) {
    return;
}, 'void', ['uint32']));
```

This is the output we get:

```
Hi, I have the flag for you just right here!
I'll just take a quick nap before I print it out for you, should only take me a decade or so!
zzzzzzzz....
Ok, I'm Up! The flag is: cGljb0NURnt3NGtlX20zX3VwX3cxdGhfZnIxZGFfZjI3YWNjMzh9
```

Decoding the base64 we get out flag: `picoCTF{w4ke_m3_up_w1th_fr1da_f27acc38}`

In ghidra we could have done the same thing but we would have to go through the entire binary to look for the flag string or replace the sleep call with nops which would have been a lot more annoying than this was.

## Bininst2:

Reusing the same python as above we can just change the binary to bininst2.exe and look at all the functions called.
This one is a lot less helpful in the debugging so we will have to look at all the calls to sys32 to see what is going on.
If we try to do all that in one script it actually overwhelms frida and it will miss a few calls so instead we want to have dedicated scripts for highlevel lower level and network and run them one at a time:

```JavaScript
console.log('[+] Hooking High-Level Win32 APIs');

const win32Hooks = {
    'kernel32.dll': [
        'CreateFileA', 'ReadFile', 'WriteFile',
        'CreateProcessA', 'GetProcAddress'
    ],
    'advapi32.dll': [
        'RegOpenKeyExA', 'RegSetValueExA'
    ]
};

for (const [moduleName, functions] of Object.entries(win32Hooks)) {
    const mod = Process.getModuleByName(moduleName);
    if (!mod) {
        console.log(`[!] Module ${moduleName} not found`);
        continue;
    }

    functions.forEach(funcName =&gt; {
        const funcAddr = mod.getExportByName(funcName);
        if (funcAddr) {
            Interceptor.attach(funcAddr, {
                onEnter(args) {
                    this.funcName = funcName;
                    console.log(`[HL] ${moduleName}::${funcName} called`);

                    // Special handling for CreateFileA
                    if (funcName === 'CreateFileA') {
                        this.fileName = safeReadString(args[^0]);
                        console.log(`    File: ${this.fileName}`);
                    }
                },
                onLeave(retval) {
                    console.log(`[HL] ${this.funcName} returned: ${retval}`);
                }
            });
        }
    });
}

```

```JavaScript
console.log('[+] Hooking Low-Level NT APIs');

const ntHooks = [
    'NtCreateFile', 'NtReadFile',
    'NtAllocateVirtualMemory', 'NtProtectVirtualMemory'
];

ntHooks.forEach(funcName =&gt; {
    const funcAddr = Module.findExportByName('ntdll.dll', funcName);
    if (!funcAddr) return;

    Interceptor.attach(funcAddr, {
        onEnter(args) {
            console.log(`[LL] ${funcName} called`);
            if (funcName === 'NtCreateFile') {
                const filenamePtr = args[^3].add(8).readPointer();
                this.fileName = safeReadUnicodeString(filenamePtr);
                console.log(`    File: ${this.fileName}`);
            }
        }
    });
});

```

```JavaScript
console.log('[+] Hooking Service APIs');

const serviceHooks = {
    'CreateServiceA': args =&gt; ({
        serviceName: safeReadString(args[^1]),
        displayName: safeReadString(args[^2])
    }),
    'StartServiceA': args =&gt; ({
        serviceName: safeReadString(args[^1])
    })
};

Object.entries(serviceHooks).forEach(([funcName, argParser]) =&gt; {
    const funcAddr = Module.findExportByName('advapi32.dll', funcName);
    if (!funcAddr) return;

    Interceptor.attach(funcAddr, {
        onEnter(args) {
            this.args = argParser(args);
            console.log(`[SRV] ${funcName} called: ${JSON.stringify(this.args)}`);
        }
    });
});

```

```JavaScript
console.log('[+] Hooking Network APIs');

const wsockHooks = [
    'send', 'recv', 'connect', 'WSASend'
];

wsockHooks.forEach(funcName =&gt; {
    const funcAddr = Module.findExportByName('ws2_32.dll', funcName);
    if (!funcAddr) return;

    Interceptor.attach(funcAddr, {
        onEnter(args) {
            console.log(`[NET] ${funcName} called`);
            if (funcName === 'send' || funcName === 'WSASend') {
                const buffer = args[^1].readByteArray(args[^2].toInt32());
                console.log('    Data:', buffer);
            }
        }
    });
});
```

Now if we look at the winapi calls we can see that it is calling CreateFileA which is returning an error:

```
[+] Hooking High-Level Win32 APIs
[*] Frida is running. Press Ctrl+C to exit.
[HL] kernel32.dll::GetProcAddress called
[HL] GetProcAddress returned: 0x7ffeec702440
[HL] kernel32.dll::GetProcAddress called
[HL] GetProcAddress returned: 0x7ffeec71bbb0
[HL] kernel32.dll::GetProcAddress called
[HL] GetProcAddress returned: 0x7ffeec6ea8c0
[HL] kernel32.dll::CreateFileA called
{'type': 'error', 'description': "ReferenceError: 'safeReadString' is not defined", 'stack': "ReferenceError: 'safeReadString' is not defined\n    at onEnt
er (/script1.js:31)", 'fileName': '/script1.js', 'lineNumber': 31, 'columnNumber': 1}
[HL] CreateFileA returned: 0xffffffffffffffff
[HL] kernel32.dll::GetProcAddress called
```

Let's look at exactly why its failing look at input and return args:

```JavaScript
// Utility function for safe string reading
function safeReadString(ptr) {
    try {
        return ptr.readUtf8String();
    } catch (e) {
        return "&lt;invalid&gt;";
    }
}

// Parse file access flags
function parseAccess(access) {
    const flags = [];
    if (access &amp; 0x80000000) flags.push("GENERIC_READ");
    if (access &amp; 0x40000000) flags.push("GENERIC_WRITE");
    if (access &amp; 0x20000000) flags.push("GENERIC_EXECUTE");
    if (access &amp; 0x10000000) flags.push("GENERIC_ALL");
    return flags.length ? flags.join("|") : "0x" + access.toString(16);
}

// Parse creation disposition
function parseCreation(creation) {
    const dispositions = {
        1: "CREATE_NEW",
        2: "CREATE_ALWAYS",
        3: "OPEN_EXISTING",
        4: "OPEN_ALWAYS",
        5: "TRUNCATE_EXISTING"
    };
    return dispositions[creation] || "0x" + creation.toString(16);
}

function hookCreateFileA() {
    // Hook both possible locations
    const modules = ["kernel32.dll", "kernelbase.dll"];

    modules.forEach(module =&gt; {
        const createFileA = Module.getExportByName(module, "CreateFileA");
        if (!createFileA) return;

        Interceptor.attach(createFileA, {
            onEnter(args) {
                this.fileName = safeReadString(args[^0]);
                this.access = args[^1].toInt32();
                this.share = args[^2].toInt32();
                this.creation = args[^4].toInt32();

                send(`\n[CreateFileA Called]
Module: ${module}
File: ${this.fileName}
Access: ${parseAccess(this.access)} (0x${this.access.toString(16)})
Share: 0x${this.share.toString(16)}
Creation: ${parseCreation(this.creation)}
`);
            },
            onLeave(retval) {
                const result =
                    retval.toInt32() === -1
                        ? "INVALID_HANDLE_VALUE"
                        : "0x" + retval.toString(16);

                send(`[CreateFileA Returned]
File: ${this.fileName}
Handle: ${result}
`);
            }
        });
    });
}

hookCreateFileA();
```

The output here is:

```
[*] Frida is running. Press Ctrl+C to exit.
[*]
[CreateFileA Called]
Module: kernel32.dll
File: &lt;Insert path here&gt;
Access: GENERIC_WRITE (0x40000000)
Share: 0x0
Creation: CREATE_ALWAYS

[*]
[CreateFileA Called]
Module: kernelbase.dll
File: &lt;Insert path here&gt;
Access: GENERIC_WRITE (0x40000000)
Share: 0x0
Creation: CREATE_ALWAYS

[*] [CreateFileA Returned]
File: &lt;Insert path here&gt;
Handle: INVALID_HANDLE_VALUE

[*] [CreateFileA Returned]
File: &lt;Insert path here&gt;
Handle: INVALID_HANDLE_VALUE
```

Let's lookup CreateFileA on the winapi docs:

```
HANDLE CreateFileA(
  [in]           LPCSTR                lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

Writing script to modify the call so that it creates ./flag.txt also keeping all the file related hooks since it may write in a separate call or even delete the file after:

```JavaScript
const handleMap = {};

function pointerToString(ptr) {
    try {
        return ptr.readAnsiString();
    } catch {
        return null;
    }
}

function logError() {
    const err = Module.getExportByName("kernel32.dll", "GetLastError");
    const getErr = new NativeFunction(err, "uint32", []);
    const code = getErr();
    console.log(`    [!] Error Code: ${code}`);
}

function replacePath(args, index) {
    const originalPtr = args[index];
    const str = pointerToString(originalPtr);
    if (!str || str.indexOf(":") === -1) {
        console.log("    [!] Invalid file path detected. Modifying...");
        const newPath = Memory.allocUtf8String("./flag.txt");
        args[index] = newPath;
        console.log("    [!] Modified File Path -&gt; ./flag.txt");
    } else {
        console.log(`    [*] Original File Path: ${str}`);
    }
}

function hookCreateFile(name, address) {
    Interceptor.attach(address, {
        onEnter(args) {
            console.log(`\n[+] ${name} called`);
            replacePath(args, 0);
            console.log(`    [*] Desired Access: 0x${args[^1].toString(16)}`);
            console.log(`    [*] Share Mode: 0x${args[^2].toString(16)}`);
            console.log(`    [*] Creation Disposition: 0x${args[^4].toString(16)}`);
            console.log(`    [*] Flags &amp; Attributes: 0x${args[^5].toString(16)}`);
            console.log(`    [*] Security Attributes: ${args[^3]}`);
            console.log(`    [*] Template File: ${args[^6]}`);

            // Force safe values
            args[^2] = ptr(0x3); // Share mode: read | write
            args[^4] = ptr(0x2); // CREATE_ALWAYS
            args[^5] = ptr(0x80); // Normal attributes... this.modified = true;
        },
        onLeave(retval) {
            const handle = retval.toInt32();
            if (handle === -1) {
                console.log("[!] CreateFileA failed. Getting error code...");
                logError();
            } else {
                console.log(`[+] ${name} returned: 0x${handle.toString(16)}`);
                handleMap[handle] = "./flag.txt";
            }
        }
    });
}

function hookWriteFile() {
    const writeFile = Module.getExportByName("kernel32.dll", "WriteFile");
    Interceptor.attach(writeFile, {
        onEnter(args) {
            const handle = args[^0].toInt32();
            const buf = args[^1];
            const len = args[^2].toInt32();
            const handleName = handleMap[handle] || "&lt;Unknown&gt;";

            console.log(`\n[+] WriteFile called`);
            console.log(`    [*] Handle: 0x${handle.toString(16)} (${handleName})`);
            console.log(`    [*] Bytes to write: ${len}`);
        },
        onLeave(retval) {
            console.log(`[+] WriteFile returned: ${retval}`);
        }
    });
}

function hookCloseHandle() {
    const closeHandle = Module.getExportByName("kernel32.dll", "CloseHandle");
    Interceptor.attach(closeHandle, {
        onEnter(args) {
            const handle = args[^0].toInt32();
            console.log(`\n[+] CloseHandle called → Handle: 0x${handle.toString(16)}`);
        },
        onLeave(retval) {
            console.log(`[+] CloseHandle returned: ${retval}`);
        }
    });
}

function hookAll() {
    const createFileA = Module.getExportByName("kernel32.dll", "CreateFileA");
    const createFileW = Module.getExportByName("kernel32.dll", "CreateFileW");
    hookCreateFile("CreateFileA", createFileA);
    hookCreateFile("CreateFileW", createFileW);
    hookWriteFile();
    hookCloseHandle();
}

console.log("[*] Frida is running. Press Ctrl+C to exit.");
hookAll();
```

```
[*] Frida is running. Press Ctrl+C to exit.

[+] CreateFileA called
    [*] Original File Path: &lt;Insert path here&gt;
    [*] Desired Access: 0x40000000
    [*] Share Mode: 0x0
    [*] Creation Disposition: 0x2
    [*] Flags &amp; Attributes: 0x100000080
    [*] Security Attributes: 0x0
    [*] Template File: 0x0
    [!] Invalid file path detected. Modifying...
    [!] Modified File Path -&gt; ./flag.txt
    [!] Modified Share Mode -&gt; 0x3 (READ | WRITE)
    [!] Modified Creation -&gt; CREATE_ALWAYS
[+] CreateFileA returned: 0x2b8

[+] WriteFile called
    [*] Handle: 0x2b8
    [*] Bytes to write: 0
[+] WriteFile returned: 0x1
```

So write file is being called after like we suspected but the file doesn't have anything. Let's look at the args to writefile and it looks like its 0 - let's increase it to 64:

```JavaScript
'use strict';

const replacementPath = Memory.allocUtf8String("./flag.txt");

function getLastError() {
    const GetLastError = new NativeFunction(Module.getExportByName("kernel32.dll", "GetLastError"), "uint32", []);
    return GetLastError();
}

function dumpHex(ptr, len) {
    const effectiveLen = Math.max(0, len);
    if (effectiveLen === 0) {
         return "&lt;Zero length specified for dump&gt;";
    }
    if (ptr.isNull()) {
        return "&lt;Invalid Pointer (NULL)&gt;";
    }

    try {
        const maxDumpSize = 256;
        const dumpLength = Math.min(effectiveLen, maxDumpSize);
        const bytes = Memory.readByteArray(ptr, dumpLength);
        let output = hexdump(bytes, {
            offset: ptr.toString(),
            length: dumpLength,
            header: true,
            ansi: false
        });
        if (dumpLength &lt; effectiveLen) {
             output += `\n      ... (showing first ${dumpLength} of ${effectiveLen} requested bytes)`;
             if (effectiveLen &gt; maxDumpSize) {
                 output += ` [Limited to ${maxDumpSize} bytes max]`;
             }
        }
        return output;
    } catch (e) {
        return `&lt;Error reading ${effectiveLen} bytes at ${ptr}: ${e.message}&gt;`;
    }
}

function interceptCreateFileA() {
    const funcName = "CreateFileA";
    const targetModule = "kernel32.dll";
    const targetFunction = Module.findExportByName(targetModule, funcName);
    if (!targetFunction) return;

    Interceptor.attach(targetFunction, {
        onEnter(args) {
            try {
                this.lpFileName = args[^0];
                this.dwDesiredAccess = args[^1].toUInt32();
                this.dwShareMode = args[^2].toUInt32();
                this.lpSecurityAttributes = args[^3];
                this.dwCreationDisposition = args[^4].toUInt32();
                this.dwFlagsAndAttributes = args[^5].toUInt32();
                this.hTemplateFile = args[^6];
                this.origPath = "&lt;Invalid Pointer&gt;";
                if (!this.lpFileName.isNull()) {
                    try { this.origPath = Memory.readCString(this.lpFileName); } catch (e) { this.origPath = "&lt;Read Error&gt;"; }
                }

                console.log(`\n[+] ${funcName} called`);
                console.log(`    &gt; File Path: "${this.origPath}" (${this.lpFileName})`);
                console.log(`    &gt; Desired Access: 0x${this.dwDesiredAccess.toString(16)}`);
                console.log(`    &gt; Share Mode: 0x${this.dwShareMode.toString(16)}`);
                console.log(`    &gt; Security Attrs: ${this.lpSecurityAttributes}`);
                console.log(`    &gt; Creation Disp: ${this.dwCreationDisposition}`);
                console.log(`    &gt; Flags &amp; Attrs: 0x${this.dwFlagsAndAttributes.toString(16)}`);
                console.log(`    &gt; Template File: ${this.hTemplateFile}`);

                const newShareMode = 0x3;
                const newCreationDisp = 0x2;

                console.log(`    [!] Modifying arguments...`);
                console.log(`        - Path: "${this.origPath}" -&gt; "./flag.txt"`);
                console.log(`        - Share Mode: 0x${this.dwShareMode.toString(16)} -&gt; 0x${newShareMode.toString(16)}`);
                console.log(`        - Creation Disp: ${this.dwCreationDisposition} -&gt; ${newCreationDisp}`);

                args[^0] = replacementPath;
                args[^2] = ptr(newShareMode.toString());
                args[^4] = ptr(newCreationDisp.toString());

            } catch (e) {
                console.error(`[!] Error in ${funcName} onEnter: ${e.stack || e}`);
            }
        },
        onLeave(retval) {
            try {
                if (retval.equals(ptr("-1"))) {
                    const error = getLastError();
                    console.log(`[!] ${funcName} failed. Return Value: ${retval}`);
                    console.log(`    [!] GetLastError(): ${error} (0x${error.toString(16)})`);
                } else {
                    console.log(`[+] ${funcName} returned Handle: ${retval}`);
                }
            } catch (e) {
                console.error(`[!] Error in ${funcName} onLeave: ${e.stack || e}`);
            }
        }
    });
}

function interceptCreateFileW() {
    const funcName = "CreateFileW";
    const targetModule = "kernel32.dll";
    const targetFunction = Module.findExportByName(targetModule, funcName);
    if (!targetFunction) return;

    Interceptor.attach(targetFunction, {
        onEnter(args) {
            try {
                this.lpFileName = args[^0];
                this.dwDesiredAccess = args[^1].toUInt32();
                this.dwShareMode = args[^2].toUInt32();
                this.lpSecurityAttributes = args[^3];
                this.dwCreationDisposition = args[^4].toUInt32();
                this.dwFlagsAndAttributes = args[^5].toUInt32();
                this.hTemplateFile = args[^6];
                this.origPath = "&lt;Invalid Pointer&gt;";
                 if (!this.lpFileName.isNull()) {
                     try { this.origPath = Memory.readUtf16String(this.lpFileName); } catch(e) { this.origPath = "&lt;Read Error&gt;"; }
                }

                console.log(`\n[+] ${funcName} called`);
                console.log(`    &gt; File Path: "${this.origPath}" (${this.lpFileName})`);
                console.log(`    &gt; Desired Access: 0x${this.dwDesiredAccess.toString(16)}`);
                console.log(`    &gt; Share Mode: 0x${this.dwShareMode.toString(16)}`);
                console.log(`    &gt; Security Attrs: ${this.lpSecurityAttributes}`);
                console.log(`    &gt; Creation Disp: ${this.dwCreationDisposition}`);
                console.log(`    &gt; Flags &amp; Attrs: 0x${this.dwFlagsAndAttributes.toString(16)}`);
                console.log(`    &gt; Template File: ${this.hTemplateFile}`);

                const newShareMode = 0x3;
                const newCreationDisp = 0x2;

                console.log(`    [!] Modifying arguments...`);
                console.log(`        - Path: "${this.origPath}" -&gt; "./flag.txt"`);
                console.log(`        - Share Mode: 0x${this.dwShareMode.toString(16)} -&gt; 0x${newShareMode.toString(16)}`);
                console.log(`        - Creation Disp: ${this.dwCreationDisposition} -&gt; ${newCreationDisp}`);

                args[^0] = replacementPath;
                args[^2] = ptr(newShareMode.toString());
                args[^4] = ptr(newCreationDisp.toString());

            } catch (e) {
                console.error(`[!] Error in ${funcName} onEnter: ${e.stack || e}`);
            }
        },
        onLeave(retval) {
            try {
                if (retval.equals(ptr("-1"))) {
                    const error = getLastError();
                    console.log(`[!] ${funcName} failed. Return Value: ${retval}`);
                    console.log(`    [!] GetLastError(): ${error} (0x${error.toString(16)})`);
                } else {
                    console.log(`[+] ${funcName} returned Handle: ${retval}`);
                }
            } catch (e) {
                console.error(`[!] Error in ${funcName} onLeave: ${e.stack || e}`);
            }
        }
    });
}

function interceptReadFile() {
    const funcName = "ReadFile";
    const targetModule = "kernel32.dll";
    const targetFunction = Module.findExportByName(targetModule, funcName);
    if (!targetFunction) return;

    Interceptor.attach(targetFunction, {
        onEnter(args) {
            try {
                this.hFile = args[^0];
                this.lpBuffer = args[^1];
                this.nNumberOfBytesToRead = args[^2].toUInt32();
                this.lpNumberOfBytesRead = args[^3];
                this.lpOverlapped = args[^4];

                console.log(`\n[+] ${funcName} called`);
                console.log(`    &gt; hFile (Handle): ${this.hFile}`);
                console.log(`    &gt; lpBuffer (Buffer Ptr): ${this.lpBuffer}`);
                console.log(`    &gt; nNumberOfBytesToRead (Max Bytes): ${this.nNumberOfBytesToRead}`);
                console.log(`    &gt; lpNumberOfBytesRead (Bytes Read Ptr): ${this.lpNumberOfBytesRead}`);
                console.log(`    &gt; lpOverlapped (Overlapped Ptr): ${this.lpOverlapped}`);

                if (this.lpBuffer.isNull() &amp;&amp; this.nNumberOfBytesToRead &gt; 0) {
                     console.log(`    [!] Potential Issue: Read length is ${this.nNumberOfBytesToRead}, but buffer pointer is NULL!`);
                }

            } catch (e) {
                console.error(`[!] Error in ${funcName} onEnter: ${e.stack || e}`);
            }
        },
        onLeave(retval) {
            try {
                const success = !retval.isNull() &amp;&amp; retval.toInt32() !== 0;
                const error = getLastError();
                let status = success ? 'Success' : 'Failure';
                if (!success &amp;&amp; error === 997) {
                    status = 'Pending (Async)';
                }

                console.log(`[+] ${funcName} returned: ${retval} (${status})`);

                if (!success &amp;&amp; error !== 997) {
                    console.log(`    [!] GetLastError(): ${error} (0x${error.toString(16)})`);
                } else if (success || (!this.lpOverlapped.isNull() &amp;&amp; error === 997)) {
                    let bytesRead = 0;
                     if (!this.lpOverlapped.isNull()) {
                        console.log(`    [*] Note: Asynchronous operation ${status}. Bytes read available later.`);
                    } else if (!this.lpNumberOfBytesRead.isNull()) {
                        try {
                            bytesRead = Memory.readUInt(this.lpNumberOfBytesRead);
                            console.log(`    [*] Bytes Read (sync): ${bytesRead}`);
                            if (bytesRead &gt; 0 &amp;&amp; !this.lpBuffer.isNull()) {
                                console.log(`    [*] Buffer data read (${bytesRead} bytes):`);
                                console.log(dumpHex(this.lpBuffer, bytesRead));
                            } else if (bytesRead === 0) {
                                console.log(`    [*] Read 0 bytes (potentially EOF or empty read).`);
                            }
                        } catch (readError) {
                            console.log(`    [!] Could not read *lpNumberOfBytesRead: ${readError.message}`);
                        }
                    }
                }
            } catch (e) {
                console.error(`[!] Error in ${funcName} onLeave: ${e.stack || e}`);
            }
        }
    });
}

function interceptWriteFile() {
    const funcName = "WriteFile";
    const targetModule = "kernel32.dll";
    const targetFunction = Module.findExportByName(targetModule, funcName);
    if (!targetFunction) return;

    const FORCED_WRITE_SIZE = 64;
    const CONTEXT_DUMP_SIZE = 256;

    Interceptor.attach(targetFunction, {
        onEnter(args) {
            try {
                this.hFile = args[^0];
                this.lpBuffer = args[^1];
                this.nOriginalBytesToWrite = args[^2].toUInt32();
                this.lpNumberOfBytesWritten = args[^3];
                this.lpOverlapped = args[^4];

                console.log(`\n[+] ${funcName} called`);
                console.log(`    &gt; hFile (Handle): ${this.hFile}`);
                console.log(`    &gt; lpBuffer (Buffer Ptr): ${this.lpBuffer}`);
                console.log(`    &gt; nNumberOfBytesToWrite (Original): ${this.nOriginalBytesToWrite}`);
                console.log(`    &gt; lpNumberOfBytesWritten (Ptr): ${this.lpNumberOfBytesWritten}`);
                console.log(`    &gt; lpOverlapped (Ptr): ${this.lpOverlapped}`);

                if (this.lpBuffer.isNull()) {
                    console.log(`    [!] lpBuffer is NULL.`);
                    if (this.nOriginalBytesToWrite &gt; 0) {
                         console.log(`    [!] Potential Issue: Original write length is ${this.nOriginalBytesToWrite}, but buffer pointer is NULL!`);
                    }
                    this.writeSizeModified = false;
                } else {
                    console.log(`    [*] Dumping buffer context (up to ${CONTEXT_DUMP_SIZE} bytes) from ${this.lpBuffer}:`);
                    try {
                        console.log(dumpHex(this.lpBuffer, CONTEXT_DUMP_SIZE));
                    } catch (dumpError) {
                        console.log(`    [!] Error during context hexdump at ${this.lpBuffer}: ${dumpError.message}`);
                    }

                    console.log(`    [!] RISKY: Forcing nNumberOfBytesToWrite to ${FORCED_WRITE_SIZE} (Original was ${this.nOriginalBytesToWrite})`);
                    args[^2] = ptr(FORCED_WRITE_SIZE.toString());
                    this.writeSizeModified = true;
                }

            } catch (e) {
                console.error(`[!] Error in ${funcName} onEnter: ${e.stack || e}`);
                this.writeSizeModified = false;
            }
        },
        onLeave(retval) {
            try {
                const success = !retval.isNull() &amp;&amp; retval.toInt32() !== 0;
                console.log(`[+] ${funcName} returned: ${retval} (${success ? 'Success' : 'Failure'})`);
                if (this.writeSizeModified) {
                    console.log(`    [*] Note: Write size was potentially forced to ${FORCED_WRITE_SIZE}.`);
                }

                if (!success) {
                    const error = getLastError();
                    console.log(`    [!] GetLastError(): ${error} (0x${error.toString(16)})`);
                } else {
                    if (!this.lpOverlapped.isNull()) {
                         console.log(`    [*] Note: Asynchronous operation.`);
                    } else if (!this.lpNumberOfBytesWritten.isNull()) {
                        try {
                            const bytesWritten = Memory.readUInt(this.lpNumberOfBytesWritten);
                             console.log(`    [*] Bytes Written (sync): ${bytesWritten}`);
                             if (this.writeSizeModified &amp;&amp; bytesWritten !== FORCED_WRITE_SIZE) {
                                 console.log(`    [!] Warning: Forced write size was ${FORCED_WRITE_SIZE}, but actual bytes written was ${bytesWritten}.`);
                             }
                        } catch (readError) {
                            console.log(`    [!] Could not read *lpNumberOfBytesWritten: ${readError.message}`);
                        }
                    }
                }
            } catch (e) {
                 console.error(`[!] Error in ${funcName} onLeave: ${e.stack || e}`);
            }
        }
    });
}

function interceptDeleteFileA() {
    const funcName = "DeleteFileA";
    const targetModule = "kernel32.dll";
    const targetFunction = Module.findExportByName(targetModule, funcName);
    if (!targetFunction) return;

    Interceptor.attach(targetFunction, {
        onEnter(args) {
            try {
                this.lpFileName = args[^0];
                this.filePath = "&lt;Invalid Pointer&gt;";
                if (!this.lpFileName.isNull()) {
                    try { this.filePath = Memory.readCString(this.lpFileName); } catch(e) { this.filePath = "&lt;Read Error&gt;"; }
                }
                console.log(`\n[+] ${funcName} called`);
                console.log(`    &gt; lpFileName (Path): "${this.filePath}" (${this.lpFileName})`);
            } catch (e) {
                console.error(`[!] Error in ${funcName} onEnter: ${e.stack || e}`);
            }
        },
        onLeave(retval) {
            try {
                const success = !retval.isNull() &amp;&amp; retval.toInt32() !== 0;
                console.log(`[+] ${funcName} returned: ${retval} (${success ? 'Success' : 'Failure'}) for path "${this.filePath}"`);
                if (!success) {
                    const error = getLastError();
                    console.log(`    [!] GetLastError(): ${error} (0x${error.toString(16)})`);
                }
            } catch (e) {
                console.error(`[!] Error in ${funcName} onLeave: ${e.stack || e}`);
            }
        }
    });
}

function interceptDeleteFileW() {
    const funcName = "DeleteFileW";
    const targetModule = "kernel32.dll";
    const targetFunction = Module.findExportByName(targetModule, funcName);
    if (!targetFunction) return;

    Interceptor.attach(targetFunction, {
        onEnter(args) {
            try {
                this.lpFileName = args[^0];
                this.filePath = "&lt;Invalid Pointer&gt;";
                if (!this.lpFileName.isNull()) {
                    try { this.filePath = Memory.readUtf16String(this.lpFileName); } catch(e) { this.filePath = "&lt;Read Error&gt;"; }
                }
                console.log(`\n[+] ${funcName} called`);
                console.log(`    &gt; lpFileName (Path): "${this.filePath}" (${this.lpFileName})`);
            } catch (e) {
                console.error(`[!] Error in ${funcName} onEnter: ${e.stack || e}`);
            }
        },
        onLeave(retval) {
            try {
                const success = !retval.isNull() &amp;&amp; retval.toInt32() !== 0;
                console.log(`[+] ${funcName} returned: ${retval} (${success ? 'Success' : 'Failure'}) for path "${this.filePath}"`);
                if (!success) {
                    const error = getLastError();
                    console.log(`    [!] GetLastError(): ${error} (0x${error.toString(16)})`);
                }
            } catch (e) {
                console.error(`[!] Error in ${funcName} onLeave: ${e.stack || e}`);
            }
        }
    });
}

console.log("[*] Frida script starting...");
console.log("[*] Attaching interceptors...");

try {
    interceptCreateFileA();
    interceptCreateFileW();
    interceptReadFile();
    interceptWriteFile();
    interceptDeleteFileA();
    interceptDeleteFileW();

    console.log("[*] Interceptors attached successfully.");
    console.log("[*] Waiting for API calls. Press Ctrl+C to exit.");
} catch (error) {
    console.error(`[!] Failed to attach interceptors: ${error.stack || error}`);
}
```

This writes `cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9` to flag.txt. Base64 decode it to get `picoCTF{fr1da_f0r_b1n_in5trum3nt4tion!_b21aef39}`
a slightly easier thing to do was to just memdump the buffer and we would have got the flag
