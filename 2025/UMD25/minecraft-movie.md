#HTML Injection bypassing DOMPurify, leading to Form Submission Hijacking (Clickjacking)

-  A React Single Page Application (SPA) where users could post content. The content was rendered using React's dangerouslySetInnerHTML after being sanitized by DOMPurify. The DOMPurify configuration allowed certain tags, including `<iframe>`, for embedding media (like YouTube). An admin bot visits submitted posts

unintended:
1. A `<form method="post">` was created targeting the application’s social endpoint (/legacy-social).
2. Hidden input fields were set to force a positive action (e.g., likes value set to 100).
3. A `<button type="submit">` was placed inside the injected form. This malicious button was styled and given the same id (dislike-button) and classes as the genuine 'Dislike' button.
4. When the admin bot attempted to click the genuine 'Dislike' button, it instead triggered the malicious form's submit action, forcing the bot to "like" the post 100 times.
5. Liking the post successfully caused the flag to be displayed on the bot's account page (AccountPage).

intended:
dom clobbering on the `window.sessionNumber` variable