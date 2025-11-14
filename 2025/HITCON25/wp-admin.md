#pearLFI -> RCE


- Login to https://localhost:8000/wp-admin using the username and password as admin:admin.
- Things to note:
    - Wordpress is read only, you cant edit wordpress code.

- Some normal features of Wordpress 6.8.2 which can be abused to RCE:
    - Theme path: 
        - use: points WordPress to the active theme folder so WP knows where to load theme templates and assets.
        - for rce: change this option so WP looks in a different base directory (e.g., a writable temporary folder) when resolving template file names. That makes WP check /tmp/... (or whatever path) for template files instead of the theme folder.

    - Post slug(post_name):
        - use: a sanitized, short, URL-friendly identifier for a post
        - for rce: set the slug to a value that, after URL-decoding inside WP, contains path traversal segments so the constructed template candidate name points outside themes (e.g., it injects ../ style segments into the template filename).

    - upload_path + Media upload
        - use: tells WP where to store uploaded media (images, PDFs) — defaults to wp-content/uploads
        - rce: set upload_path to a writable system location (e.g., under /tmp) and then upload a file

    - Template loader (get_single_template() / locate_template())
        - use: builds a prioritized list of possible PHP template filenames (like single.php, single-post-<slug>.php) and checks theme folders/core to find the right file to include.
        - rce: by controlling the theme base (stylesheet) and the slug (after decoding), we inject a candidate filename that resolves to an arbitrary file on disk; locate_template() file_exists() check finds it and WP includes it.

    - pearcmd.php
        - use: a utity library from PEAR that perform several package/helper actions- not part of wp
        - rce: once we can include that file via the template loader, we call it with parameters that use its file-write functionality to create a PHP file (a simple web shell) inside the writable /tmp directory.
        - note: we cannot write WP code, but we can include and misuse an existing script on the host that already offers file-writing behavior; that is the gadget that converts LFI → writeable shell.


So in summary:
- WordPress has a template loader that asks: “What file should I include to render this post?” It builds names like `single-post-<slug>.php`.

- It checks folders in order — first the active theme folder, then a fallback folder.

- You (as admin) can change:

    - the slug of a post (post_name),

    - the stylesheet (which tells WP where the theme files live), and

    - the upload_path (where uploaded files go).

You can also upload media files (which creates folders under upload_path).

So you can control both the suffix of the template filename (via slug) and the base folder WP checks (via stylesheet).

To solve:

- When you edit a slug, WP sanitizes it so you can’t type ../ directly.

But the template code calls urldecode($object->post_name) — so if you set the slug to a URL-encoded traversal like:
```
%2f%2e%2e%2f%2e%2e%2fusr%2flocal%2flib%2fphp%2fpearcmd
```
urldecode() turns that into /../../../../usr/local/lib/php/pearcmd — path traversal appears after decoding. That becomes the suffix in the template name `single-post-<decoded-slug>.php`.

So URL-encoding lets you sneak path traversal into the generated template filename.

WP looks for templates like:
`[THEME_PATH]/single-post-[SLUG].php`

- If you set the stylesheet option to something that points into `/tmp` (e.g. ../../../../tmp), and the slug decodes into a traversal targeting some system PHP file (pearcmd), the constructed path can resolve to a real file on disk when file_exists() is checked. Example:

    - stylesheet value → ../../../../tmp (so WP will check /tmp/...)

    - slug (decoded) → /../../usr/local/lib/php/pearcmd

    - combined candidate → /tmp/single-post-/../../usr/local/lib/php/pearcmd.php
which resolves to /usr/local/lib/php/pearcmd.php if the path collapses that way.

If that file exists, WP includes it → Local File Inclusion (LFI).

- Now we need to get writeable location to put the shell

Even though WP code is read-only, you can create directories under paths that are writable by the container (like /tmp) using the uploads feature:

    - Change upload_path to /tmp/single-post-.

    - Upload any media from the admin UI. WP will create `/tmp/single-post-/<year>/<month>/....`

That creates `/tmp/single-post-` so /tmp/single-post- now exists and you can write to places under /tmp.

So you control THEME_PATH (point it at /tmp) and you can create folders under /tmp via uploads. 

- What is pearcmd?

    - pearcmd.php. It’s part of PEAR and, when included and called with certain query parameters, it can perform file operations (e.g., create files).
    - By making WP include pearcmd.php (via the slug + stylesheet trick) and calling it with crafted parameters, you can cause it to write a new PHP file into /tmp — e.g. `/tmp/shell.php` containing something like `<?php system($_GET[0]); ?>`.

- Uploading the shell

    - After /tmp/shell.php exists, set another post’s slug (URL-encoded) so that single-post-<slug>.php resolves to /tmp/shell.php.

Visit that post in the browser and pass a parameter that the shell reads and executes (e.g., ?0=cat /flag or similar). Because WP included /tmp/shell.php, the shell runs and executes your command → RCE.

references:

- To find pearcmd in application container:
`find / -name '*.php'`
-
Final payloads; 

/?p=6&+config-create+/<?system($_GET[0]);die();?>+/tmp/shell.php


/?p=10&0=/readflag

