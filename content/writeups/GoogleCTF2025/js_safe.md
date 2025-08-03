+++
title = "JS Safe"
date = "2025-07-04"
authors = ["Arun Radhakrishnan"]
+++

### Description
We're given a website that is designed to store secrets. Secrets are xored with the correct flag and put into local storage, and can be unlocked by providing the flag as input to the unlock function.
The flag is encrypted (simple rotation) and then heavily scrambled before being stored into the variable 'pool'. When checking the flag, it is unencrypted and unscrambled characterwise and checked with the input characterwise.

All this happens on client side, no connection or request is made to server... so we can tamper with it.

### The Safety Valves
1. The first issue preventing us from tampering with the code comes from the instrument and instrument prototype functions. These functions associate some function calls with a price. The step value gets incremented by the price each time that particular function is run. So if we tamper the code (by say, maybe editing the render function), not enough function calls are made, and therefore the step value isn't incremented properly.

And if the step value isn't incremented properly, we'll have issues unscrambling the 'pool' during flag check (as shown in the code snippet below)
```js
    while (!window.success) {
        j = ((iﾠ|| 1)* 16807 + window.step) % 2147483647;
        ...
    }
```

The only way around this is to not include or delete any function calls that might happen before the flag is fully checked.
The silver lining, however, is that this only applies to certain function calls, not basic operations like string concatenation etc. (we'll return to this fact in a moment)

2. Another issue with changing the code, is this line
```js
Function`[0].step; if (window.step == 0 || check.toString().length !== 914) while(true) debugger; // Aﾠcooler wayﾠto eval```
```
This places a check on the function 'check' and ensures that it hasn't been changed or messed around with. In theory, we would have to find some way out of this (maybe even delete this line somehow). But turns out, that the check is very simple. As long as the function length is 914, we have no issues. So we'll just make sure that our tampered code remains 914 characters.

3. Another safety feature added is CSP (Content Securtiy Policy) in the meta tag at the start of the file. Usually this is a pretty solid security feature. They've mentioned two sha-256 hashes, and only those scripts which have those hash can run. But again, our code is entirely local, so we can literally just change the sha-256 hash in the csp to whatever the hash of our tampered code and then run that file locally.

### The Exploit
Keeping these three in mind, we will have try to make changes to the check function code.
One of the main things we want to change is this:
```js
if (flag[0] == pool[j % pool.length] && (window.step < 1000000))
```
We don't know the flag, and we don't want to guess. So this condition has to go. 

A simple fix is to just replace it with
```js
if (1)
```
One potential issue: maybe the code was designed such that only some iterations would satisfy the condition, but we will make an educated guess that it won't be the case.

Now that our check function is running properly, we have to figure out how to get some info out of it. We could maybe print the j value in each iteration (but that might affect the step count), we could store each j value and print at end, or wait...

We could literally just store all the values of:
```js
pool[j % pool.length]
```
which would be all the characters of the flag in order. And since accessing array elements and appending to string don't seem to modify the function, we should be good to go.

So we make the following changes

```diff
window.check // Checks password
 = function() {
    Function`[0].step; if (window.step == 0 || check.toString().length !== 914) while(true) debugger; // Aﾠcooler wayﾠto eval```
    // Functionﾠuntampered,ﾠproceed to 'decryption` & check
    try {
    window.step = 0;
    [0].step;
    const flag = (window.flag||'').split('');  
- let iﾠ= 1337, j = 0;
+ let iﾠ= 1337, j = 0, z = '';
    let pool =ﾠ`?o>\`Wn0o0U0N?05o0ps}q0|mt\`ne\`us&400_pn0ss_mph_0\`5`;
    pool = r(pool).split('');
    const double = Function.call`window.stepﾠ*=ﾠ2`;ﾠ// To the debugger,ﾠthis isﾠinvisible
    while (!window.success) {
        j = ((iﾠ|| 1)* 16807 + window.step) % 2147483647;
-        if (flag[0] == pool[j % pool.length] && (window.step < 1000000)) {
+        if (1) { z += pool[ j % pool.length ];
            iﾠ= j;
            flag.shift();
            pool.splice(j % pool.length, 1);
            renderFrame();
            double();
            if (!pool.length&&!flag.length) window.success = true;
        }
    }
+    console.log(z);
    } catch(e) {}
}
```
Ensure to modify the spacing etc. so that the length of the function is the same. And also change the second sha256 hash in the csp protection to be the hash of our modified code.

And voila, the exploit is ready. All we have to do is run the code, open console (use the preserve log setting, otherwise the output will get deleted), type in "anti(debug)" and then "unlock("CTF{...}")" (... can be anything really) and you get your output (you might have to scroll up a bit to find it).

1M_4_C7F_p14y32_4N71_d38U9_721cK5_d0n7_w02K_0n_m3