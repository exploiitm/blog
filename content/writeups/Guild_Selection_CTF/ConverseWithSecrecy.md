+++
title = 'Converse with secrecy'
date = '2024-09-05'
authors = ["Achintya J"]
+++



# Converse with secrecy

We've been given a pcapng file, which is a `wireshark` network capture image. If we open this file using wireshark (or alternatively, you can just using strings).

Actually, strings is an easier method. So, use the following command to display all the strings in the pcapng file. 

		strings conversation.pcapng

You can probably read a bunch of text messages. If you analyse them you'll see that it expects us to find the Game of the year awardee for the year when Will Smith got defensive. 

If we google that year, it was 2022. Thus, checking the records for game of the year winners of 2022, we get this one name frequently, 

		Elden Rings

our answer is therefore elden rings! Formatting it properly gives the flag (according to the description)

`flag: iitmCTF{elden_rings}`
