+++
title = 'Oh my admin'
date = '2024-09-05'
authors = ["Achintya J"]
+++

In this challenge, we've been given a login page and asked to sign in as admin. When we enter the credentials, 

		username: admin
		password: admin

we get the message: **"Wrong SessID"**

What this means is, the server internally checks the user's request for the session ID to verify if they're really admin. We can intercept this request using `burpsuite`.

1. Launch burpsuite, head over to the proxy tab and open a new browser instance. (if you don't have burpsuite installed, it's a pretty simple process so don't worry, just google)

2. In the new browser, enter url and then switch the intercept mode on. 

3. use credentials as mentioned above and inspect the request

you'll see a header named `session_id` which contains a `base64 encoded string`. We decode it to find that its of the format `<username><someNumber>`(in our case `admin<somenumber>`). For some specific number this will give us the flag (atleast that's what comes to mind initially).

However, there exists a sneakier way. What we want to do, is raise an exception in the server, and see if we get traceback messages. This means we can read the backend code that is being implemented and read the flag directly!

4. Raise an exception by `passing an empty string as the session_id`. This will throw an Error and allow you to see the traceback. Now that we've verified we can see the traceback, we'll get to reading the code

5. In the session_id we are entering a base64 encoded string. This implies that there is a possibility for the backend server to have a `base64 decode statement` in it's main function. Since, we know its running a python based flask server, it'll probably be using the base64 library to decode. 

Hence, one crazy thing we can do is `mess with the base64 characters`. If we enter invalid base64 characters in the session_id it will throw an error and allow us to do a traceback. If we do this, there is a special function which is throwing an error (as expected, its the `base64.decode()` part which didn't work) and upon clicking on it, the flag is visible in plaintext!

Turns out that the session_id was `admin<number>` but the number ain't visible,  but that don't matter anymore anyway.

`flag: FLAG{b6k3d_c00k13ez}`
