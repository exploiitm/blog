+++
title = "exploit 'em - my cysec journey"
date = 2024-07-02
authors = ["Arivoli R"]
+++


## Freshie Year 2023-24
A time when cybersecurity club didn't even exist yet; I dual-booted to linux because of **EE1103** with Prof. Anil Prabhakar who basically said:
	_“If you don’t use Linux, you’re not a programmer.”_ 
(He also said people who can’t touch type aren’t programmers, but I could already touch type so I was very proud.) 

90% of cs students in my batch still use Windows, which I find pretty funny. That push gave me a solid head start with command line, as I also learnt every shell trick possible from [Overthewire/Bandit](https://overthewire.org/wargames/bandit/)

I dove into pwn, starting with [tryhackme's pwn101](https://tryhackme.com/room/pwn101), religiously following [Razvioverflow's tutorials](https://www.youtube.com/watch?v=0_merdYty4Y&list=PLchBW5mYosh_F38onTyuhMTt2WGfY-yr7). I even tried [LiveOverflow's BinExp series](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN ) (*goated*) but was too lazy to complete it back then. I eventually went back later and finished the whole playlist; I wish I'd done it earlier.

By end of Sem-1 all clubs were recruiting deputy coordinators (DCs), but cysec wasn't :( 
The club was too new, so they took only coordinators. I begged Kartha (club founder; head in 2023) to let me join as a DC, lol. 

I was lucky to find someone equally obsessed with cybersecurity my now co-head, Abhinav (bro got optiver intern too skilled smh). 
We solved Bandit, pwn101, and PortSwigger's web exploitation labs together. Beyond that, we didn't have much time for more.

At some point, we started doing CTFs (Capture-the-Flag events). Shaastra CTF was one of our first, back when we didn’t even know what ctftime.org was (you don’t need to know yet lol). We placed top 600 in picoctf 2024 and felt goated (Kartha said "come top 100 else skill issue" smh)

Mid Sem-2, I approached Prof. Chester Rebeiro (Cybersecurity Club faculty advisior) to work under him. I got to work on **DTIME** — a Windows malware execution framework, where I learnt a lot of OS concepts, C++, x86 assembly and windows internals. I also interned at RISE lab as a cysec intern summer 2024. From the intern I learnt how to write simple malware that work on windows (like keyloggers etc (totally haven't done sus stuff with this knowledge)). 
Around this time, I became a coordinator in the **coolest club** in insti ;)

--- 
## Sophie Year 2024-25

Abhinav and I then duo’d up to qualify for the RVCE × IITB CTF finals, placing **14th out of 1,000**+ nationally. It’s not earth-shattering, but back then I was jumping up and down. 
Regardless, got a free trip to Bangalore sponsored by IITM hehe (free food also bro it was so good). In 3rd and 4th sems, we played a bunch of CTFs with fellow coordinators and recruited ~30 DCs at the end of their Sem-1.

Fast forward — I was part of the **2025 MITRE eCTF** team. We placed **7th internationally**, beating grad students from MIT, NYU, BYU, and competing on par with UIUC, CMU, Purdue, UCLA, UMich, etc. We were one of **only 9 teams** (out of 130+ universities) with a completely unbroken system throughout the year.  
LinkedIn version:
> _(Achieved 7th rank internationally at MITRE eCTF 2025, maintaining an unbroken defense; one of only 9 teams to do so, alongside top universities like CMU, Purdue, MIT, UCLA, UMich, and others.)_

eCTF in short: a 3-month competition — 1 month to design and secure a system, 2 months attacking other universities’ systems. Points for both defense and offense; ranked accordingly. We were the **best in APAC**.

We wrote the system in Rust for memory safety (learnt the language in <1 month due to crunch). We exploited multiple cryptographic vulnerabilities and discovered an entirely new attack surface — **hardware exploits**; by short-circuiting the microprocessor at precise times to skip security checks. Pretty sure we’re the first from IITM, and possibly the first Indian undergrad team, to pull that off. Felt amazing :)  
(There’s a very funny video of us jumping around after our first successful hardware glitch, might play it at the aspiring DCs meet.)

I always felt like I should have joined a comp team. But this experience more than made up for it, and honestly taught more than any comp team could have. (no offense lol; two of my eCTF teammates that were/are in comp teams can vouch for this). 
Every cysec project I've worked on has taken me deeper into low-level systems. No complaints there, xD.

---
## Junior Year 2025-26 :)
Right after eCTF wrapped up, I became head of exploiitm (2025-26). Now working on building a **secure real-time operating system** with some very fun people; lets see how that goes :)

First big task as head? Coordinator recruitment for the 24-batch. We dropped the apps right after endsems and made them **brutally hard**, at least 3× tougher than my own coord app. Just because so many people wanted in. The result? Most number of coord apps in all of CFI this tenure, plus some absolutely cracked solves.apps

I was honestly shocked people could full-solve; a year ago, I would’ve been too intimidated to even try. An ex-coord DMed me: "*this app is overkill*".
I replied, "*24b is too smart vro theyll cook*".
They did, exactly as predicted :D

Looking back, I shouldn't have been surprised. Just a few months earlier, **two cysec DC** **teams** had already placed top-100 in picoCTF (Abhinav and I were somewhere in the 500s the year before), plus multiple top-3 India finishes in other CTFs. It was obvious my juniors were learning faster and performing better than me, or anyone in my batch.

Honestly, I’m low-key jealous of my coordinators for the peer group they’ve built. In just their first month online, they carried me to a **top-50 finish in GoogleCTF** (top team from India) and an **international 4th in JuniorCryptCTF** — stuff that felt impossible just a year ago.

If this is what they’ve done in [month one](https://www.linkedin.com/posts/exploiitm_ctf-cybersecurity-googlectf-activity-7346089383009165312-DUpU?utm_source=share&utm_medium=member_desktop&rcm=ACoAAEhD9B8B4DLToVVSXs-Wcqh3rwIpSKWR3mY)… I can’t wait to see what we pull off by the end of the year.

---
## To now :)  Aug 2025
There's more — like getting admin access to IITM websites, buying ₹400 worth of hostel nite food coupons for ₹1 minutes before the event, and a bunch of other fun stories. 

I’m writing this because a lot of people have been asking me about cybersecurity and the club in general. Hopefully this gives a better picture. 

To any kid reading this years later, good luck and have fun :P

