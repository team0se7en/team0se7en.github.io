# Csawquals20 Smallsurp


## Writeup summary

- Challenge Info
- TL-DR
- Analysis of the server code
- Bypass Hmac Verification
- Assemble Secrets and Get Flag

## Challenge Info

Your APT group scr1pt_k1tt13z breached into a popular enterprise service, but due to inexperience,
you only got the usernames of the administrators of the service, and an encrypted password for the root admin.
However, you learned that the company had a key agreement ceremony at
some point in time, and the administrators keys are all somehow connected to the root admin's. `http://crypto.chal.csaw.io:5005/`

#### Attachment:

- server_handout.py

```python
#!/usr/bin/env python3
import os
import base64
import hashlib
import random

import flask

from gen_db import DATABASE

app = flask.Flask(__name__)
app.secret_key = "dljsaklqk24e21cjn!Ew@@dsa5"

N = int("00ab76f585834c3c2b7b7b2c8a04c66571539fa660d39762e338cd8160589f08e3d223744cb7894ea6b424ebab899983ff61136c8315d9d03aef12bd7c0486184945998ff80c8d3d59dcb0196fb2c37c43d9cbff751a0745b9d796bcc155cfd186a3bb4ff6c43be833ff1322693d8f76418a48a51f43d598d78a642072e9fff533", 16)

g = 2
k = 3

b = random.randint(0, N - 1)
salt = str(random.randint(0, 2**32 - 1))

def gen_seed():
    return random.randint(0, N - 1)

def xor_data(binary_data_1, binary_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])

def modular_pow(base, exponent, modulus):
    if modulus == -1:
        return 0

    result = 1
    base %= modulus

    while exponent > 0:
        if exponent % 2:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus

    return result


def hmac_sha256(key, message):
    if len(key) > 64:
        key = sha256(key).digest()
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = xor_data(b'\x5c' * 64, key)
    i_key_pad = xor_data(b'\x36' * 64, key)
    return hashlib.sha256(o_key_pad + hashlib.sha256(i_key_pad + message).digest()).hexdigest()


def hasher(data):
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)


app.jinja_env.globals.update(
    gen_seed=gen_seed,
    modular_pow=modular_pow,
    N=N,
)


@app.route("/", methods=["GET", "POST"])
def home():
    if flask.request.method == "POST":
        username = flask.request.form.get("username")
        if username is None:
            flask.flash("Error encountered on server-side.")
            return flask.redirect(flask.url_for("home"))

        hmac = flask.request.form.get("computed")
        if (hmac is not None):
            return flask.redirect(flask.url_for("dashboard", user=username, hmac=hmac))

        try:
            pwd = DATABASE[username]
        except KeyError:
            flask.flash("Cannot find password for username in database")
            return flask.redirect(flask.url_for("home"))

        try:
            A = int(flask.request.form.get("token1"))
        except Exception as e:
            flask.flash("Error encountered on server-side")
            return flask.redirect(flask.url_for("home"))

        if A is None:
            flask.flash("Error encountered on server-side.")
            return flask.redirect(flask.url_for("home"))

        if A in [0, N]:
            flask.flash("Error encountered on server-side. >:)")
            return flask.redirect(flask.url_for("home"))

        xH = hasher(salt + str(pwd))
        v = modular_pow(g, xH, N)
        B = (k * v + modular_pow(g, b, N)) % N
        u = hasher(str(A) + str(B))
        S = modular_pow(A * modular_pow(v, u, N), b, N)
        K = hashlib.sha256(str(S).encode()).digest()
        flask.session["server_hmac"] = hmac_sha256(K, salt.encode())
        return flask.jsonify(nacl=salt, token2=B)
    else:
        return flask.render_template("home.html")


@app.route("/dash/<user>", methods=["POST", "GET"])
def dashboard(user):
    if "hmac" not in flask.request.args:
        flask.flash("Error encountered on server-side.")
        return flask.redirect(flask.url_for("home"))

    hmac = flask.request.args["hmac"]
    servermac = flask.session.get("server_hmac", None)
    print(hmac, servermac)
    if hmac != servermac:
        flask.flash("Incorrect password.")
        return flask.redirect(flask.url_for("home"))

    pwd = DATABASE[user]
    return flask.render_template("dashboard.html", username=user, pwd=pwd)


if __name__ == "__main__":
    app.run()
```

- database.txt

```text
Jere:
Lakisha:
Loraine:
Ingrid:
Orlando:
Berry:
Alton:
Bryan:
Kathryn:
Brigitte:
Dannie:
Jo:
Leslie:
Adrian:
Autumn:
Kellie:
Alphonso:
Joel:
Alissa:
Rubin:
```

- encrypted.txt

```text
cbc:254dc5ae7bb063ceaf3c2da953386948:08589c6b40ab64c434064ec4be41c9089eefc599603bc7441898c2e8511d03f6
```

## TL-DR

we have a webiste `http://crypto.chal.csaw.io:5005/` containing a login form where the server authenthicate users and add the hmac to the session, there is a `/home` where server verify the hmac and show the user password so as an attacker we have to get all users password and then assemble them with SHAMIR SECRET SHARING SCHEMA to decrypt the flag.

## Analysis of the server code

by checking the server code we can say that it is a flask application that has 2 routes:

- `/` : handle POST request where we can submit the username and password the essential POST parametre are `{token1, username }` when we check the source code of the webpage we can see that `token1` is an int value constant that is passed when user log in, then it is making some validation on the value of `token1` :

```python
 try:
        A = int(flask.request.form.get("token1"))
    except Exception as e:
       flask.flash("Error encountered on server-side")
        return flask.redirect(flask.url_for("home"))

    if A is None:
        flask.flash("Error encountered on server-side.")
        return flask.redirect(flask.url_for("home"))

    if A in [0, N]:
        flask.flash("Error encountered on server-side. >:)")
        return flask.redirect(flask.url_for("home"))
```

we can notice one thing that is strange `if A in [0, N]:` which mean that A can be any value except 0 and N, then server calculate the hmac based on the value of A and password then save it in the session:

```python
xH = hasher(salt + str(pwd))
v = modular_pow(g, xH, N)
B = (k * v + modular_pow(g, b, N)) % N
u = hasher(str(A) + str(B))
S = modular_pow(A * modular_pow(v, u, N), b, N)
K = hashlib.sha256(str(S).encode()).digest()
flask.session["server_hmac"] = hmac_sha256(K, salt.encode())
```

and then return the `salt` used in the calculation of hmac and return `B`

- `/dash/<user>`: it check the `hmac` we send with the `hmac` saved in the session if its the same it will redirect to `dashboard.html` which will show us the password

## Bypass Hmac Verification

To bypass the hmac verfication we have to get back to how the hmac is calculated and get back on what we have noticed back then. So what we can controll is the `username` and the value of `A`.
By looking more deeper in the calculation of the hmac we can notice it is calculation `S = modular_pow(A * modular_pow(v, u, N), b, N)` and this value will be used in sha2 hash to get the hmac so if we can know the value of `S` we can calculate the hmac locally and bypass it. but how can we get the value of `S`.

In the first part we noticed `A` is validated in a strange way `if A in [0, N]:` this is to make sure S !=0 but we can send A=2\*N which will make `S=0` and the salt is sent to us we can calculate the hmac locally !!! .let's scipt it :

```python
BASE_URL = 'http://crypto.chal.csaw.io:5005/'
for user in users:
    s = requests.Session()
    data = {
        "username": user,
        "token1": 2*N,
    }
    response = s.post(BASE_URL, data=data)
    y = json.loads(response.content.decode())
    salt = y["nacl"]
    S = 0
    K = hashlib.sha256(str(S).encode()).digest()
    hmac = hmac_sha256(K, salt.encode())
    data = {
        "computed": hmac,
        "username": user,
    }
    response = s.post(BASE_URL, data=data)
    content = response.content.decode()
    hash = re.findall(r'<td>(.*)</td>', content)[1]
    print(hash)
```

with this script we can get a list of hashes of each user .

## Assemble Secrets and Get Flag

Now that we have all the passwords we can see a pattern in the passwords for example here is the first one `1:c4ee528d1e7d1931e512ff263297e25c:128` and in the description they said that the passwords are connected to the root password( the flag ), so we need a way to assemble those passwords, after wasting a lot of time testing out different methods i finnaly found the correct one which is using the SHAMIR SECRET SCHEME And was able to decrypt and get the flag `flag{n0t_s0_s3cur3_4ft3r_4ll}`
here is what i did to decrypt it :

```python
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Cipher import AES
from binascii import unhexlify
shares = []
for idx, hash in enumerate(hashes):
    print(idx)
    shares.append((idx+1, int(hash, 16)))
key = Shamir.combine(shares)
print(key)
IV = unhexlify('254dc5ae7bb063ceaf3c2da953386948')
cipher = AES.new(key, AES.MODE_CBC, IV)
c = unhexlify(
    '08589c6b40ab64c434064ec4be41c9089eefc599603bc7441898c2e8511d03f6')
print(cipher.decrypt(c))
```

