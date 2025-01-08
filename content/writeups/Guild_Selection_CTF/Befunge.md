+++
title = 'Befunge'
date = '2024-09-05'
authors = ["Achintya J"]
+++


This challenge gives us this cryptic text, and nothing else

		Vielaedhc tdtycsus us one xrto. Cra kiryyc ntje prie rv td uzet rd onus uv cra tooedzez one hcmeisehaiuoc hyam's hickor sessurd wZ.btom.ud/qebuktzuyab. U'p faso ctkkudx neie t muo prie sr onto one orry lauklauk gribs etsuyc. Kirks or cra uv cra sryjez onus.

The first thought the comes to mind when I see plaintext encryption is simple `rot` like caeser cipher. So, I tired rotating the letters for all possible combinations and nothing made sense.

The next way to attack this is using frequency analysis. Note that frequency analysis in general, always works. If the plain text has been encoded using a single key and a letter `x` always maps to a letter `y`, then frequency analysis is the way to go.


So, head over to 

		https://www.101computing.net/frequency-analysis/

and start guessing and checking. You just want the text to resemble plaintext english, so, make use of all the grammar that you know! (Note that frequency analysis actually means something different, its based off of the idea that some letter are more frequent than other letters and therefore in cases when a text is encrypted while preserving the frequencies, we can determine the original letters using just that).

I like to do it this way, cause it seems more fun, but you might want to write a program for this (if the text is too big, then sure a python script is necessary). 

The final decrypted message looks like this:

		FREQUENCY ANALYSIS IS THE GOAT. YOU PROLLY HAVE MORE OF AN IDEA ON THIS IF YOU ATTENDED THE CYBERSECURITY CLUB'S CRYPTO SESSION *D.KATB.IN/*EKIPADILUK. I'M JUST YAPPING HERE A BIT MORE SO THAT THE TOOL QUIPQUIP WORKS EASILY. PROPS TO YOU IF YOU SOLVED THIS.


Now, thats obviously a `katbin` link. If you've never seen katbin before, its okay. A quick googing of this link format will tell you everything you need to know. You'll notice that we only need the part `KATB.IN/*EKIPADILUK` and katbin links are always lowercase so `katb.in/*ekipadiluk`. 

What comes in place of the star? There are only 2 options, so we'll just try both (`x` and `z`). Trying with `z` opens up katbin with the following message,

		Use your brains and decode this!
		+[----->+++<]>+.+++++++.+.-----------.------.-[->++++<]>+.----------.++++++.[->+++<]>.+++++.+++++.-----.++++++++++.++++++.+[->+++<]>.+++++++.++++++++++++.+++++++.[->+++++<]>++.-[->++++<]>+.----------.++++++.---.+++[->+++<]>.+++.[--->+<]>----.+++[->+++<]>++.++++++++.+++++.+++++.
		Good luck :)

Googling this format will let you know that this is a famous (or infamous) programming language called `brainfuck`. We can find sites that will execute this script for us, so we needn't worry! (head over to: `https://www.dcode.fr/brainfuck-language`). Executing this, gives us the flag!

flag: `iitmctf{hope_you_didnt_fry_your_brains}`
