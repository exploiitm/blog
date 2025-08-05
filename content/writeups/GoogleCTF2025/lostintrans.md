+++
title = "Lost in Transliteration"
date = 2025-08-05
authors = ["Abizer Lokhandwala"]
+++


This is a really fun question that combines multiple vulnerabilities to get XSS.

### 1. Initial Analysis

We can first look at the main app and see that it really just renders a page that translates Greek to Latin characters. It also looks at the Unicode category and only allows **letters** and **other letters** through, and Unicode-escapes the rest.

The vulnerability here is that it allows `OtherLetter`, which is not necessarily just Greek and Latin but also includes Chinese, Japanese, etc., which are allowed through **without escaping**.

### 2. The Encoding Snippet

```csharp
private static bool IsSafeChar(char c)
{
    var cat = char.GetUnicodeCategory(c);
    // We don't consider ModifierLetter safe.
    var isLetter = cat == UnicodeCategory.LowercaseLetter ||
                   cat == UnicodeCategory.UppercaseLetter ||
                   cat == UnicodeCategory.OtherLetter;

    return isLetter || char.IsWhiteSpace(c);
}

private static string JsEncode(string? s)
{
    if (s is null)
    {
        return "";
    }
    var sb = new StringBuilder();
    foreach (char c in s)
    {
        if (IsSafeChar(c))
        {
            sb.Append(c);
        }
        else
        {
            sb.Append("\\u");
            sb.Append(Convert.ToInt32(c).ToString("x4"));
        }
    }
    return sb.ToString();
}
```

### 3. JavaScript Snippet That Renders the Page

```js
// Load Lit directly from the CDN.
import {
  LitElement,
  html,
} from 'https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js';

function transliterateGreekToLatin(text) {
    const greekMap = {
        '\u03b1': 'a', '\u03b2': 'b', '\u03b3': 'g', '\u03b4': 'd', '\u03b5': 'e', '\u03b6': 'z', '\u03b7': 'i', '\u03b8': 'th',
        '\u03b9': 'i', '\u03ba': 'k', '\u03bb': 'l', '\u03bc': 'm', '\u03bd': 'n', '\u03be': 'x', '\u03bf': 'o', '\u03c0': 'p',
        '\u03c1': 'r', '\u03c3': 's', '\u03c2': 's', '\u03c4': 't', '\u03c5': 'y', '\u03c6': 'f', '\u03c7': 'ch', '\u03c8': 'ps',
        '\u03c9': 'o',
        '\u03ac': 'a', '\u03ad': 'e', '\u03ae': 'i', '\u03af': 'i', '\u03cc': 'o', '\u03cd': 'y', '\u03ce': 'o',
        '\u03ca': 'i', '\u03cb': 'y',
        '\u0391': 'A', '\u0392': 'B', '\u0393': 'G', '\u0394': 'D', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'I', '\u0398': 'Th',
        '\u0399': 'I', '\u039a': 'K', '\u039b': 'L', '\u039c': 'M', '\u039d': 'N', '\u039e': 'X', '\u039f': 'O', '\u03a0': 'P',
        '\u03a1': 'R', '\u03a3': 'S', '\u03a4': 'T', '\u03a5': 'Y', '\u03a6': 'F', '\u03a7': 'Ch', '\u03a8': 'Ps',
        '\u03a9': 'O',
        '\u0386': 'A', '\u0388': 'E', '\u0389': 'I', '\u038a': 'I', '\u038c': 'O', '\u038e': 'Y', '\u038f': 'O',
        '\u03aa': 'I', '\u03ab': 'Y'
    };

    let transliteratedText = '';
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        transliteratedText += greekMap[char] || char;
    }
    return transliteratedText;
}

// Main component, available as <greek-transliteration-app>.
class GreekTransliterationApp extends LitElement {
    static properties = {
        greekText: { type: String },
        latinText: { type: String },
    };

    constructor() {
        super();
        this.greekText = '';
        this.latinText = '';
    }

    createRenderRoot() {
        return this;
    }

    handleInputChange(event) {
        this.greekText = event.target.value;
        this.latinText = transliterateGreekToLatin(this.greekText);

        const url = new URL(window.location.href);
        url.searchParams.set('q', this.greekText);
        window.history.replaceState({}, '', url.toString());
    }

    render() {
        return html`
            <div class='container'>
                <h1>Greek to Latin Transliterator</h1>

                <input
                    type='text'
                    autofocus
                    .value='${this.greekText}'
                    @input='${this.handleInputChange}'
                    placeholder='Enter Greek text here...'
                >
                <p class='example-text'>Examples: &Pi;&upsilon;&theta;&alpha;&gamma;&omicron;&rho;&alpha;&sigmaf;, &Sigma;&omega;&kappa;&rho;&alpha;&tau;&eta;&sigmaf;, &Alpha;&rho;&iota;&sigma;&tau;&omicron;&tau;&epsilon;&lambda;&eta;&sigmaf;</p>

                <div style='margin-top: 10px;'>
                    <span class='output-label'>Latin Transliteration:</span>
                    <div id='outputBox'>${this.latinText}</div>
                </div>
            </div>
        `;
    }
}

customElements.define('greek-transliteration-app', GreekTransliterationApp);

// Load the query from request.
// TODO: Maybe we should move this directly to HTML into a <script> tag?
window.q = 'TEMPLATE_QUERY_JS';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
for (const payload of PAYLOADS) {
  if (window.q.toLowerCase().includes(payload)) {
    throw new Error('XSS!');
  }
}

const mainApp = document.createElement('greek-transliteration-app');
mainApp.greekText = window.q;
mainApp.latinText = transliterateGreekToLatin(window.q);
document.body.appendChild(mainApp);
```

### 4. The File Serving Logic

```csharp
app.MapGet("/", (string q = "", string ct = "") =>
{
  return Results.Text($@"
        <!doctype html><meta charset=utf-8>
        <body>
        <link href='https://fonts.googleapis.com/css2?family=Palatino+Linotype&amp;display=swap' rel='stylesheet'>
        <link rel=stylesheet href='/file?filename=style.css&amp;ct=text/css'>
        <script type=module src='/file?filename=script.js&amp;q={HttpUtility.UrlEncode(q)}&amp;ct=text/javascript'></script>
      ",
      contentType: "text/html");
});

app.MapGet("/file", (string filename = "", string? ct = null, string? q = null) =>
{
  string? template = FindFile(filename);
  if (template is null)
  {
    return Results.NotFound();
  }
  ct ??= "text/plain";
  if (!IsValidContentType(ct))
  {
    return Results.BadRequest("Invalid Content-Type");
  }
  string text = template
      .Replace("TEMPLATE_QUERY_JS", JsEncode(q));
  return Results.Text(text, contentType: ct);
});
```


More importantly, this also means I can request any file with a content type that may be different. For example, in JS and HTML, the syntax for comments is different.

Look at this snippet:

```js
// Load the query from request.
// TODO: Maybe we should move this directly to HTML into a <script> tag?
window.q = 'TEMPLATE_QUERY_JS';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
```

Here in a normal JS file, the `<script>` tags would be useless. But if we serve the JS as HTML, then it becomes:

```html
<script> tag?
window.q = 'TEMPLATE_QUERY_JS';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>
```

And our input is reflected exactly in `window.q`, so if we escape the string, it will just be able to execute arbitrary JS code.

---

### 5. Avoiding the Unicode Escape

If the Unicode category is not a letter, the program will Unicode escape our input. But since we can define the encoding—if we set the encoding to some arbitrary charset that Chromium will not recognize—it defaults to `windows-1252`.

Using this, input of any Unicode character that has the byte `0x8C` will translate to a `'` in the script.

With this, we have successfully escaped the string. But we are still somewhat limited in the code we can execute, since it’s kind of hard to find characters that won’t break syntax.

---

### 6. Constructing the Payload

Now that we have escaped the string, we still need to make the script syntactically valid so it can execute.

First, we need to do something about the `tag?` that is right after the script tag—it will cause the app to error out. Luckily, we can append `: abcd`. This makes the expression:

```
tag ? window.q='asa' : abcd
```

But again, our `:` and `'` will be preceded by weird characters. So we need to fix that.

We can do this by using the `in` operator:

```
tag ? window.q='asa' in ppp : abcd
```

Now we’ve solved the syntax issues, but we still need to execute the code. We can do this by using **tagged templates**, like `setTimeout`.

We define the character preceding `'` as a variable = `setTimeout`, and then call that variable.

---

### 7. Final Payload

```
ct=text/html;charset=x-Chinese-CNS&q=x%E5%87%98in+%E5%98%84alert%0avar+%E5%A2%89setTimeout%0a%E5%AB%9Dalert(1)//%E5%AB%9D%0avar+tag%0a%E5%AB%9D
```

