+++
title = 'O Captain My Captain'
date = '2024-09-05'
authors = ["Achintya J"]
+++

# O Captain My Captain

This challenge gives you a lot of directories and files. It'll be very improbable to go through each of them and manually search. Luckily we have `grep`!

		grep -ir ctf .

If we use this command, we are looking inside all the files in the current directory (looking at their strings that is...) and seeing if any of them match the pattern `ctf` (a case insensitive search because of **-i**). 

Why `ctf`? Its because we assume that the flag is hidden inside some file and the flag format contains the letters "ctf". Hence, it makes sense (you could also search for `iitm` or `iitmctf` as you like, you should likely try everything that comes to your mind).

Now that it gives us an image, lets open that. 

		open 5d/9d/9d/lol.png

This is definitely `hydra`! Now, if you know about password cracking then you'd know that **hydra** is a pretty popular tool in that field. However, in this case, its not meant for that. This is another grep search! (again, you might be tempted to "crack" png file using hydra somehow, but you'll soon learn its not worth it). 

		grep -ir hydra .

This gives us a file. Using strings on that file, we can see the strings (duh) and get the flag!

flag: `iitmctf{kbgud_kinda_impressed_lol}`
