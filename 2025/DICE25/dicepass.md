https://blog.maple3142.net/2025/03/31/dicectf-2025-quals-writeups/en/#dicepass

- exploit the custom password manager extension to retrieve a flag hidden in the bot's vault
-  Bypass 1 (Origin Pollution): The background script tracks the tab's origin. Since the content script runs in all frames, including iframes, the attacker could embed an iframe pointing to the target origin (e.g., https://dicepass.dicec.tf). This tricks the background script into thinking the attacker's tab is the target origin, allowing the critical check await remote.hasPasswordFor(id) to pass, which is necessary for triggering autofill.

- Bypass 2 (Code Execution): After achieving origin pollution, the attacker used DOM clobbering to pollute usernameInput.value. This allowed them to retrieve the content script's window object via dicepass.prevUsername.ownerDocument.defaultView. This object was then used to call setTimeout(string), achieving code execution in the content script context, as this function was not blocked by the content script's Content-Security-Policy (CSP).

- Final Exfiltration: Once code execution was achieved, the attacker modified the bot's encrypted vault (stored in chrome.storage.local). They swapped the username and password from the entry containing the flag (vault) into the known, accessible entry (vault), and then called remote.getLogin(id) to exfiltrate the flag.