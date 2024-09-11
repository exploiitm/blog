+++
title = 'Report to me!'
date = '2024-09-05'
authors = ["Achintya J"]
+++

# Report to me!

We've been given a `tar` file. We can open this guy using 

		tar -xvf report.tar

This gives us a directory called `report`. Inside there is a `docx` file and a zipped file. The zipped file is locked!

If we open the `report.docx` file, we can see that it contains some texts. However, what we can't see are the characters that have been whittened out! If you press `ctrl+A` on your keyboard you'll see that highlighted! 

Note that it's in general a good practise to press ctrl+A and check if there are whitespaces or characters you are missing. 

Now that you have the passcode to open the zipped file, we can unzip it and then go inside.

Inside is an image and an audio file. At first nothing seems wrong, but if you open the audio file through a frequency spectrum analyser (another good tip for audio challenges: always open using frequency spectrum analyser), you'll see a passcode being printed out.

Such embeddings are common in audio CTFs, and there are many tools that allow you to do something like that. The resulting audio may be useless but if you combine this channel with a valid one, and lower this one's decibles, you'll have an almost perfect steganography!

Now that we have the passcode, we can use `steghide` to extract a hidden file from inside the `image.jpg` file. How do I know something is hidden there? I don't, it simply a trial and error process. You need to exhaust your options first and then look elsewhere. 

		steghide --extract -sf "image.jpg" 

When prompted to enter the password, enter what you found there and boom. You have the flag.
