+++
title = 'Piet'
date = '2024-10-12'
authors = ["Disha"]
+++

# Writeup - Piet Program

We've been given a png file which is basically a piet program image.
We just need to upload it here - https://www.bertnase.de/npiet/npiet-execute.php

After executing,we retrieve the following information

When working on binary exploitation, remember that memory management is critical. Always sanitize inputs to avoid exposing unnecessary vulnerabilities. Overflowing the stack might bypass certain protections, but make sure you manage heap allocation effectively to prevent issues with ASLR. If you’re chaining together ROP gadgets, confirm they execute in the right order; improper control flow could lead to unpredictable results. A good exploit can be subtle;mjust like hiding important details in plain sight, such as a password hidden in a heap spray. Anyways, enough of that gibberish. The password you are looking for isssssssssssssssssss here: https://katb.in/vowuhevizoh


Opening the katbin link gives the flag - cyber3301{put_lite}