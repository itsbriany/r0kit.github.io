# XSS

You will normally encounter popular frameworks that have XSS countermeasures in place. You can try the following in an attempt to bypass them:

* Search for reflected errors in the app. Sometimes error messages don't escape HTML to the page. 
    * Learn the technology stack the app is using -> search for **functions that escape error messages.**
    * Sometimes, you might need to bypass multiple technology stacks. For example, django may not escape an message, but react might.

## XSS in React.js (methodology could also apply to other frond-end JS frameworks)

* Search for data being rendered with `${JSON.stringify({data})}`. `JSON.stringify` will turn any data you have into a string and render it on the page. This is common in apps because it was a code smell introduced in many `redux` applications that people have used as boilerplate code.
* Check for places where you can define attributes to HTML tags. For example, a tag with `<a href="USER_DEFINED_INPUT"></a>` can become `<a href="javascript: alert('XSS')"></a>`
* Check for calls to `dangerouslySetInnerHTML` and `eval()`.
