🌋 The Legend of Arxignis and the Moat

In the age of digital kingdoms, where empires rise and fall at the speed of code, there stands a fortress unlike any other — Arxignis, the Citadel of Fire.

Forged from lines of code and tempered by the flames of countless cyber battles, Arxignis was built for one purpose: to protect your realm.

But no fortress stands alone.

Surrounding Arxignis is Moat — not water, but an invisible, intelligent barrier that shifts and shimmers like living magic. It sees threats before they even know they exist. When invaders approach — bot armies, malicious payloads, or the darkest zero-day beasts — Moat awakens.

With a whisper of algorithmic incantation, it analyzes intent, bends logic, and casts away the unworthy.

Attackers see nothing but endless reflection — their own attacks bouncing back into the void. To them, it’s as if your citadel never existed. To you, it’s silent peace behind walls of flame and light.

Because this is your Citadel, your Arx, your Ignis.
And with Moat, the fire never reaches your gates. 🔥

![Story](./images/story.png)

# Run locally


## Docker build
```
docker build -t moat .
```

## Docker run
```
docker run --cap-add=SYS_ADMIN --cap-add=BPF \
--cap-add=NET_ADMIN moat --iface eth0 \
--arxignis-api-key="" --arxignis-rule-id=""
```
