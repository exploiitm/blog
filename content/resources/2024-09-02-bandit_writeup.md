+++
title = "Bandit Writeup"
date = 2024-09-02 
authors = ["Tushar Jain"]
+++
## Bandit 0
`ssh` command & reading the readme file through `cat` command : 

`ssh bandit0@bandit.labs.overthewire.org -p 2220`

## Bandit 1
We were given a dash(-) file. To open it, we cannot directly use `cat -` etc. But we can use the following command instead : `cat ./-`

## Bandit 2
In this level, we were given a file name with spaces in it. We just have to pass it to `cat` as a string argument : `cat "spaces in this filename"`

## Bandit 3
We have a directory called inhere in this level. Lets go inside it and check the contents.
We see that the directory is empty. Let’s check for hidden files using `ls -la` and we will find the file

## Bandit 4
When we go inside inhere directory, we see 10 different files and we are asked to open only the human readable one. We use `file` command to check contents. Only `file007` has ASCII text and it contains the password.

## Bandit 5
When we go inside inhere directory, we see a lot of other directories. Given the constraints, we run the command `du -b -all | grep 1033` to get required file where `-b` flag prints file size in bytes, `-all` flag analyses all files and `grep` searches for `1033`. We can also use one more flag `-h` for human readable.

## Bandit 6
First let’s go to root directory by command `cd /` .
Then use command : `find -user bandit7 -group bandit6 -size 33c`

## Bandit 7
We were given that password lies next to word millionth. So we can use `cat data.txt | grep "millionth"`.

## Bandit 8
For finding unique string, we will first sort it and then get unique string from `uniq` command. I made `new.txt` in `tmp` as that was the only location to make new files.

We use the following commands :
- `cd temp`
- `touch new.txt`
- `sort ~/data.txt > ./tmp/new.txt`
- `uniq -u ./tmp/new.txt`

## Bandit 9
In this level, we just need to search for `=` in strings in `data.txt`. `strings data.txt | grep "="`

## Bandit 10
To decode base64, we use it with `-d` flag

## Bandit 11
We can write a code to decode ROT13 or we can just go to a website(rot13.com) to solve it for us.

## Bandit 12
Creating another directory called `this` in `tmp`, copyting `data.txt` to `new.txt`, then reversing `xxd` by using flag `-r`. We get files that are compressed multiple times. Decompressing them gives our password.
- `cd /tmp/`
- `mkdir this`
- `touch my_file`
- `xxd -r new.txt > my_file`
- And then multiple decompressions using `gzip -d`, `bzip2 -d` or `tar -xf`

## Bandit 13
For this all we need to do is use private key given to connect to bandit14 using `-i` flag.
We use  `ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220`

## Bandit 14
We first find the password in `/etc/bandit_pass/bandit14` as specified in level 13. Then we send the password to localhost using `nectat`. Command : `cat bandit14 | nc localhost 3000`

## Bandit 15
Since the post is SSL Encrypted, we connect it through the following command : `openssl s_client -connect localhost:3001`

## Bandit 16
We are given 1000 ports that we have to check. I created a bash script in `new` directory in `tmp`.

Bash Script : 

```
#! /bin/bash
i=31000
while [ 32000 -ge $i ]
do
	echo $i
	openssl s_client -connect localhost:$i
	i=$((i+1))
done
```
Now we will have a few such instances where we would be asked to put the data (password of prev level in this case). After doing that, we can modify the script to check for later numbers and accordingly get the required correct answer.

Then we store the private key in `sshkey.private` and use following commands :
- `chmod 600 sshkey.private` // Permission
- `ssh -i sshkey.private bandit17@bandit.labs.overthewire.org -p 2220`

## Bandit 17
To get the difference between two files, we can use `vimdiff`. Command : `vimdiff passwords.old passwords.new`

## Bandit 18
We can run a command inside ssh without logging in by directly writing the command after our usual ssh command. Command : `ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme`

## Bandit 19
If we use `ls -l` , we can check that the owner of this file is bandit20. Thus we open the folder we need as bandit20 user and get the password. Command : `./bandit20-do cat /etc/bandit_pass/bandit20`

## Bandit 20
In this level, what we need is a port that gives password of level 20 as output.
What we do is echo the password in a separate port that we create(I created port `4200`). We use flags `-l`(listen) `-p` (to specify port) and end the command with `&` to run it in background.

Commands: 
- `echo $password | nc -l -p 4200 &`
- `./suconnect 4200`
