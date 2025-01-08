+++
title = 'Something Is Askew'
date = '2024-09-05'
authors = ["Achintya J"]
+++

# Something Is Askew

### This is an SQL injection challenge

Try out different prompts from this GitHub repo "https://github.com/payloadbox/sql-injection-payload-list". 

The main difference here is that there is an additional bracket that comes into picture. 

Thus to properly escape the query and comment it out, you'll need to take care of this bracket as well. The prompt that works (others similar to this will also work) is:

		username: admin') or '1'='1'--
		password: <any random stuff>

Note that we've used single quotation marks, this is because a double quotation was being interpreted differently by the server (try and check it out!)

`flag: iitmCTF{PpP0Oo5tgr85Ql}`
