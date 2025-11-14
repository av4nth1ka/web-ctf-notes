https://adragos.ro/dice-ctf-2025-quals/#websafestnote

- dompurify
- The objective was to steal the flag that the admin bot stored in a note
-  User-submitted notes were sanitized using DOMPurify.sanitize() before being saved to localStorage. The application also explicitly blocked several characters from the input: `#, @, ', ", &, \, -, +.`
- The application had no Content Security Policy (CSP) to worry about, and DOMPurify allowed the insertion of `<style>` elements by default, pointing toward a potential CSS injection vulnerability.

1. Leveraging Session History

- Although the admin's flag note was overwritten in localStorage when the attacker submitted their payload, the flag value remained restored in the visible `<input>` field on the original page when the browser navigated back.
- The goal required the flag (in the input field) and the attacker's injected content (HTML/CSS loaded from localStorage) to exist simultaneously on the same page.

2. Bypassing Back/Forward Cache (BFCache)

- Modern browsers use BFCache to prevent JavaScript from re-running on history navigation, which interfered with the planned HTML injection.

- The BFCache had to be forcibly purged, either by adding an unload event listener via an injected script or by performing a series of unnecessary navigations (e.g., 6 navigations) to push the target page out of the cache memory, requiring a final jump back using a large negative history step (e.g., history.go(-8)).

3. CSS Injection for Data Exfiltration
- The chosen method was CSS injection combined with input validation properties, since direct XSS was blocked by DOMPurify.

- Standard value-based CSS selectors (e.g., `input[value^=dice]`) do not update in real-time on dynamic inputs where session history restores data.

- The solution involved using real-time selectors like input:valid and input:invalid.

- The attacker injects a fake form containing an `<input name=note pattern=^dice.*>`. The browser's session history fills this fake input with the sensitive flag value.

- The injected `<style>` block then uses the validation state (:valid or :invalid) to leak data character by character using the background:url() property. Depending on whether the guessing pattern matches the flag prefix, a request is sent to an attacker-controlled endpoint (/start or /invalid), enabling binary search to extract the entire flag