![](attachments/Pasted%20image%2020250724195326.png)
# The Challenge

![](attachments/Pasted%20image%2020250724195820.png)
The aim of this challenge is to reach this flag on the top of the tree here. Problem is, you can't jump that high. Nothing which is in the game by intent lets you jump this high or even gets you to this y-level, There must be some other glitch that exists in the rom which lets us get up there.

# The Solution

Recall from the solution to MAME A, the game only renders those sprites which are in the view of the camera, Indeed this extends to wasps as well.
![](attachments/Pasted%20image%2020250724200151.png)
(another conveniently placed wasp)

I first got the idea of this glitch existing on accident
.![](attachments/Pasted%20image%2020250724200825.png)
I noticed that if I had made the game summon multiple wasps at the same time. I tried to reproduce this because maybe there was something that would happen from having a boatload of wasps being summoned.
![](attachments/ezgif-53b1cf4cc38ad6.gif)
yay

by scurrying over to the right, you can bring the wasp spawn zone to the edge of the rendering area, this confuses the script.

After that it's as simple as first stopping any more wasps from spawning, and then using the glitched out wasps as a platform to get the flag.

To actually access the flag, you need to use the same rendering gimmick as MAME A, where if a sprite goes off screen.
![](attachments/ezgif-550b5415c0a944.gif)

It's easier to show than to tell.

