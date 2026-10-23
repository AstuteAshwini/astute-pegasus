# Console AI in Pegasus

The **Console AI** button on a client's page opens a small chat window that asks that client's OCI Console AI.
It works through your own OCI sign-in, using the free Console AI that's already in the OCI Console.

Oracle has no API for Console AI, so a small **helper** on your own computer does the asking. It opens the
client's OCI Console in a browser window, where you sign in once (MFA included). That window then minimizes and
stays signed in in the background. The chat window in Pegasus sends your questions to the helper. The helper
types them into Console AI and sends back the reply.

* Your OCI password, your console session, your questions and the answers all stay on your computer. The
  Pegasus server never sees any of them.
* The helper listens on this computer only (127.0.0.1:8765). It answers only the Pegasus page.
* It types questions and reads replies, nothing else. It never clicks anything in a reply, so it can't
  approve an action Console AI proposes.

## Start the helper (Windows)

Double-click `start-console-ai.bat` in this folder. The first run takes a minute to set itself up. Keep its
window open while you use Console AI; close it, or press Ctrl+C, to stop it. Stopping it signs you out of
every client.

The helper accepts requests from `https://pegasus.beastute.com` by default. To use a different Pegasus
address:

```
start-console-ai.bat --origin https://other-pegasus.example.com
```

Without the .bat file:

```
pip install -r requirements.txt
python -m playwright install chromium
python -m pegasus_console_ai
```

## Use it

1. In Pegasus, open a client whose OCI tenancy and region are set (Settings → OCI Console).
2. Click **Console AI**, then **Sign in to OCI**.
3. A console window opens. Sign in there. It minimizes by itself, and the chat window says you're signed in.
4. Ask your questions. Each client gets its own sign-in, and each sign-in lasts as long as OCI keeps the
   session alive. When it ends, the chat window asks you to sign in again.

If your browser asks whether Pegasus may "access devices on your local network", allow it. That's the page
talking to the helper on your own computer.

## Options

* `--background offscreen`: moves signed-in windows off the screen instead of minimizing them.
* `--debug`: saves screenshots and the page structure for every question. Send that folder if Console AI
  answers aren't coming through, which can happen when Oracle changes the console.
* `--timeout 180`: waits longer for slow answers. The default is 120 seconds.
* `python -m pegasus_console_ai chat --tenancy miracostaoci --region us-phoenix-1`: chat in the terminal
  without Pegasus.
