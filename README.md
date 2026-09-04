The Spotify player Lua I used to use ([Neverlose Market](https://neverlose.cc/market/item?id=yrvHej))
is no longer working, because its authentication/callback server appears to be
offline.

I still wanted the feature, so I ended up making my own version, heavily
inspired by the original. Since there is not much reason to keep something like
this private, I decided to release it for free and make the source available as
well.

It lets you control Spotify directly from CS:GO through Neverlose, without
having to constantly tab out of the game.

Credit where it is due: the original is by Brotgeschmack, who built it and kept
it running for a long time. None of his code is in here — this was written from
scratch, working from screenshots of his — but the idea and the layout are his.

> **Spotify Premium is required.** Not only for the playback controls.
>
> Everything here goes through Spotify's Web API, including just *reading* what
> is playing — so the app you create has to have **Web API** enabled, and that
> option is greyed out for free accounts. A free account therefore cannot
> complete the setup on its own.
>
> It can still *view*, with the controls dead, if someone with Premium adds it
> to their app and shares that Client ID — Development Mode allows 5 users per
> app. The controls need Premium on the listening account as well.

---

## Features

* Play / pause, previous / next track
* Seek by clicking the progress bar
* Volume control
* Shuffle and repeat
* Currently playing song, artist, album and album art
* A HUD player in two styles — a full panel, or a compact strip — that you can
  drag anywhere on screen
* A bar docked under the Neverlose menu, for when you only want it while the
  menu is open
* A clantag that shows what you are playing, or an animated `spotify.lua`
  signature that stays in step between everyone running the Lua

Colours, sizes, position and which elements show are all adjustable. The
defaults are themed to sit with Neverlose's own menu, so it looks like it
belongs there out of the box.

I may add more styles, deeper customization and some ideas of my own later on.

---

## Setup

1. Go to [developer.spotify.com/dashboard](https://developer.spotify.com/dashboard)
   and create an app. Name it whatever you like.
2. Set the Redirect URI to exactly `http://127.0.0.1:8888/callback`. There is a
   **Copy redirect URI** button on the Auth tab — it has to match character for
   character.
3. Tick **Web API**, then save.
4. Copy the Client ID into the Auth tab.
5. Press **Connect Spotify** and approve it in your browser.
6. Press **Check auth status** to confirm it worked.

There is no account to make, nothing to sign up for, and no server of mine
involved anywhere.

---

## How it works

The original Lua relied on an external server as part of its Spotify
authentication flow. Once that server went offline, new users could no longer
authenticate and the Lua effectively became unusable.

This version does not depend on a permanently hosted callback server. Spotify's
OAuth flow still needs somewhere to send you after you approve access, so
instead of a website, the Lua opens a small listener on `127.0.0.1:8888` and
serves that redirect itself. Your browser talks to your own machine, and the
loop closes with nobody in the middle. Authorization uses PKCE, the OAuth flow
designed for apps that cannot keep a secret, so nothing confidential has to ship
inside a script anyone can read.

You bring your own Client ID rather than sharing a built-in one. A Spotify app
in Development Mode allows 5 additional users, so a shared key would run out almost
immediately — and it would make me the single point of failure all over again,
which is the whole thing this was meant to avoid.

After authentication the Lua talks to Spotify's Web API directly for playback
information and player actions.

Your login is stored by Neverlose against your account rather than in a file,
and it is encrypted with a key derived from your machine, so a copy that ends up
anywhere else is refused and that person is asked to connect their own account.
The permissions it holds cover reading and controlling playback and nothing
else — no email, no password, no payment details.

The exact implementation is in the source for anyone interested in the details.

---

## Open Source

This project is free and open source.

Feel free to use the code, modify it, learn from it, or build your own version
on top of it. Improvements and contributions are also welcome — and if it ever
breaks, you do not have to wait on me to fix it.

The whole thing is one file, `spotify.lua`, and it is commented throughout.

A few things are worth knowing before you change anything, because none of them
are obvious and each one cost me an evening: menu items are userdata rather than
tables, menu text can carry invisible colour escapes that `print` will not show
you, renaming a tab or item resets its saved value, a Lua chunk may only declare
200 locals, `os` and `io` do not exist in the sandbox, and nothing reached from
the render callback may block. Each is commented where it matters.

If you redistribute or build upon the project, please follow the terms of the
included [license](LICENSE) (MIT).

This project is not affiliated with Spotify, Neverlose, or the creator of the
original Spotify Lua.
