# Entry Point Regulation Prototype Chrome Extension

This prototype Chrome extension allows for the implementation of Entry Point Regulation (EPR) on a given web site.  Sites with regulated entry points limit their exposure to reflected cross-site scripting vulnerabilities and cross-site request forgery.

Disclaimer: This is not an official Google product.

## EPR Implementation for Web Sites

To EPR-enable a site, three steps are required:

1) List out valid site entry points in a manifest file (/epr-manifest.json).  Once installed in Chrome at the client, the EPR Chrome extension is responsible for enforcing the rules specified in a site's EPR manifest.  Currently EPR manifests are specified for a given fully qualified domain name.  (In the future, this may be extended to allow different paths on a domain to have individually maintained manifests.)

2) Serve the following HTTP response header from the domain:

```
X-EPR: 1
```

This header lets the EPR Chrome extension know to download and store the EPR manifest file.  It's best if the X-EPR header is served via web server configuration rather than app-specific configuration, so that it will be served on all HTTP responses.

3) Install the EPR prototype Chrome extension on client browsers.


## Example EPR Manifest

The background.js file contains a hardcoded example manifest, complete with comments.  (See eprDataStatic.)  The epr-manifest.json file contains the same manifest, just without comments.  Edit epr-manifest.json as you'd like and host it at the root.  

Eg: https://www.[Your EPR-enabled website].com/epr-manifest.json


## More Information

TODO: Link to future EPR blog post

EPR Google Group: https://groups.google.com/forum/#!forum/epr-list

See background.js for a list of TODOs for future improvements to the EPR Chrome extension.
