+++
title = 'Protogame'
date = '2024-09-09'
authors = ["Achintya J", "Yukash"]
+++



In this challenge we are given a C++ program, a helper file and a netcat address. If we try to connect to the address, we can see that there is a lot of things going on here!

### Stage 0

This stage is where we understand the program. Reading the `cpp` file, we can see that the code for 2 levels. The helper file contains all the functions that are not normally defined in cpp (like ProtoBossStatus) and all the classes are also present in the helper file (like ProtoBoss).

The code for stage 1 says that we're supposed to choose 2 characters out of 4 (in the `Choosecharacter()` function). The characters have a varying degree of skills, relating to the hitpoints and the attack they have. We're supposed to kill the protoboss in this round. (hmm doesn't seem so hard)

The code for stage 2 says that we're supposed to pick how much ever hitpoints we want, but the protoboss will have an attack power of 3 times that. It's also evident that to kill the protoboss here, we'll have to attack twice (cause our attack power is 100), but protoboss will kill us in one go...

### Stage 1

The four characters that we have are:

		Proto1 : Proto1 has the highest damage but also has the lowest health in the game
		Proto2 : Proto2 can't deal any damage but can heal the other character if it's alive
		Proto3 : Proto3 has mediocre damage and a health enough to sustain few attacks from ProtoBoss
		Proto4 : Proto4 has the highest health while it has the lowest damage

We'll have to find a way to kill the protoboss so the most logical choice would be `Proto1` and `Proto2`, cause Proto1 will hit him hard and Proto2 will heal. However, the problem is **Protoboss levels up!** He gains attack points depending on the current round and after `51` rounds, he basically has god level status and can one-kill all the protos.

If we calculate, we'll never be able to kill protoboss in 51 rounds, without dying first if we choose any of the 6 possible combinations! What we're going to exploit is this piece of code

           	if(P1.ID != 2){
                    P1.move(P1.ID , P1 , ProtoBoss) ;
                }
                else{
                    P1.move(P1.ID , P2 , ProtoBoss) ;
                }
            }
            else{
                if(P2.ID != 2){
                    P2.move(P2.ID , P2 ,  ProtoBoss) ;
                }
                else{
                    P2.move(P2.ID , P1 , ProtoBoss);
                }
            }

What this is saying is, if the P1.ID != 2 (which will be true as it'll definitely be 1) then we move Proto1, just as we normally would. And if P2.ID is not 2 (which won't be trust as it'll be 2), then we move P2.

The cool thing is, when P2.ID is 2, then we move P1 and when P1.ID is 2 we move P2. ID will be 2 for proto2, which heals everyone. Now, the boss damage increases and keeps increasing... when we reach round 30, the boss damage is more than INT32_MAX! 

Hence, we'd have reached an integer underflow condition and subtracting this value from the hitpoints, in fact adds to it (cause you're subtracting a bigger negative number, which means you're adding a big number)! So, autoplay will continue this, until you will...

Note that, __you needed proto2 to sustain proto4 until round 30__. Any other proto other than 4 would've died before reaching round 30 no matter how much proto2 tried to heal it.


### stage 2

Now in this stage, we've been asked to enter a number between 0 and INT_MAX (2147483647). Whatever we choose, this will be our hitpoints, but we're doomed anyway cause protoboss's attack is 3 times this!

Let's look at the relevant code to see any vulnerabilities,

     if(c == 'A'){
            ProtoBosshitpoints -= damage ;
            if(ProtoBosshitpoints <= 0){
                Stage2Status(ProtoBosshitpoints , ProtoBossdamage , hitpoints , damage);
                cout << Stage2WinText ; Stage2Win();
                return true ;
            }
            Stage2Status(ProtoBosshitpoints , ProtoBossdamage , hitpoints , damage); 
            cout << Protobossturn ; 
            int originalhitpoint = hitpoints ;
            hitpoints = hitpoints - ProtoBossdamage ;           
            if(originalhitpoint < hitpoints){
                slp();
                cout << Impossible ; hitpoints = 0 ;         
            }     
            else if(-INT32_MAX < hitpoints && hitpoints < originalhitpoint){
                hitpoints = 0 ;
            }       
            if(hitpoints == 0){
                Stage2Status(ProtoBosshitpoints , ProtoBossdamage , hitpoints , damage); slp();
                cout << Stage2LossText; slp(); return false ;
            }
            else{
                continue ;
            }
        }

This is what happens when we attack. Note that, in order to win we have to somehow attack twice, but one hit from protoboss and we're dead... **or are we**?

Look at this,

		else if(-INT32_MAX < hitpoints && hitpoints < originalhitpoint){
			hitpoints = 0 ;
		}       


Its checking if our `hitpoints` is higher than -INT32_MAX. What if it's less than that? Well, it'll just continue as if nothing happened. What about our hitpoints then? It'll be lower than -INT32_MAX, so negative! This means in the next round, we'll again reach the `continue` bit while our health goes even more negative. This means we'll win!

How do we reach that negative hitpoint? INT32_MAX is 2147483647, and we know that protoboss's attack is 3 times whatever number we choose. Let's say we chose `x`. Protoboss's hitpoints is `3x`. What we need is, to solve this equation,

		x-3x <= -2147483647
		or
		x-3x = -2147483648

When protoboss attacks us, we want out final hitpoints to go below -INT32_MAX. Thus, `x` comes out to be `1073741824`. This means that, if we choose this specific number, then protoboss's attack will be just enough to push our final hitpoints below -INT32_MAX and hence, out of the restrictions of the program!

Use this, and get the flag.

flag: `IITM{R6G_pRo7O_f1Ag}` 
