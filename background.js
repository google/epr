// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


// Hardcoded EPR manifest (unused, currently)
// Normally download epr-manifest.json instead
var eprDataStatic =
  {
    "manifests":
    [
      {
       "site": "https://[Your EPR-enabled website]",
       "maxAge": 31536000,
       "reportUrl": "https://[Report URL]",   /* Currently ignored */
       "defaultNavBehavior": "block",   /* Currently ignored */
       "defaultResBehavior": "block",   /* Currently ignored */
       "rules":
       [
         /*
            This is the list of allowed entry points
            path: string for full path comparison (don't combine w/regex)
            regex: regex for full path comparison
            types: one of: navigation, stylesheet, script, image, xhr, other
            allowData: Does this entry point allow data passed via querystring, hash or POST?
         */
         { "path": "/", "types": [ "navigation" ], "allowData": false },
         { "regex": "^/\\d+$", "types": [ "navigation" ], "allowData": false },
         { "path": "/image", "types": [ "image" ], "allowData": true },
         { "regex": "^/(scoreboard|random|favorites|recentvisits|create)$", "types": [ "navigation" ], "allowData": false },
         { "regex": "^/(recent|popular|metrics|template|search)$", "types": [ "navigation" ], "allowData": true },
       ]
      }
    ]
  };

// Wipe out example in eprDataStatic, defer to downloaded manifest
// Comment this out to use the hardcoded manifest above
eprDataStatic = { "manifests": [ ] };

var eprData = { "manifests": [ ] };

var refererTracking = { };

// Todo:
//   - Take some action in the event ReDoS is detected, beyond just informing the user
//     See comments below in checkRegex
//   - Advanced manifest features
//     - reportUrl
//     - defaultNavBehavior / defaultResBehavior
//     - Manifest expiration
//   - Make sure manifests are scheme-specific so it's not possible to serve a manifest for an HTTPS site via the HTTP version of that site
//   - Docs say: "Also synchronous XMLHttpRequests from your extension are hidden from blocking event handlers in order to prevent deadlocks."
//     - Determine if there is a problem w/this...  XHR observed to go through, so this seems to be a no-op.
//   - Use bookmark API to monitor for added bookmarks and add them to bookmarkUrls
//   - Tie into logic for when browser cache is cleared so manifests are cleared as well
//   - Synchronous re-download and re-evaluation of manifests if a block operations happens on a cached manifest (see TODO in regulator())

// Other misc notes:
//   - Requests to pass unvalidated if origins...
//     ...match what's currently input to the Omnibox
//       - Ack, can't really do this...
//         - Better idea: allow all top-level blank-referer GET navigations that have no querystring or hash (path-based XSS is rare)
//         - Maybe we open this up to allow any referer?  (or just any GET request w/o querystring or hash)  Then we don't need the
//           allowData flag in the manifest to specify if querystring/hash/postdata is allowed.
//           - I'm leaning towards not doing this, but it's one one thing to consider.
//     ...are in the user's bookmarks
//       - Done
//     ...or are in the user's history, just because we can grovel that too, and these show up as suggestions in the omnibox
//       - ...or not.  Seems unnecessary.  There's some pretty odd stuff in my own omni-box drop-down
//       - Can key off of the transition type
//     ...anything else we can / should grovel through?
//     Use async methods to build up state to compare at the time of the webRequest

var worker;
var pathAnchor;
var regexTestFinished;
var regexTestDomain;
var bookmarkUrls;

// If the regex we died on last time doesn't complete in 5 seconds...
function checkRegex()
{
  if (!regexTestFinished)
  {
    worker.terminate();

    // A little unclear if we should take action here or even advise any action.
    // Maybe just offer to report it to the web site?  Is there any reasonable way to fix the user's configuration without unwanted side effects?
    alert("It looks like " + regexTestDomain + " may have served you a buggy Entry Point Regulation regex, and this caused your browser to be slow.");
  }
}

function bootWorker()
{
  regexTestFinished = true;
  if (localStorage["ReDoS-flag"])
  {
    worker = new Worker('reWorker.js');

    regexTestDomain = localStorage["ReDoS-flag"];

    regexTestFinished = false;
    worker.addEventListener('message', function(e) {
      if (e.data == true) regexTestFinished = true;
    }, false);

    // Test the regex with data, using a worker.  If it takes >5 seconds, declare that a bogus regex has been detected and prompt the user.
    // Otherwise, don't prompt, leave things as-is.  The user just happened to close the browser at a bad time.
    worker.postMessage({path: localStorage["ReDoS-path"], regex: localStorage["ReDoS-regex"]});

    setTimeout(checkRegex, 5000);

    localStorage.removeItem("ReDoS-flag");
    localStorage.removeItem("ReDoS-path");
    localStorage.removeItem("ReDoS-regex");
  }
}

// Get referer header
function getReferer(headers)
{
  var referer = null;

  for (var i = 0; i < headers.length; i++) {
    if (headers[i].name === 'Referer') {
      referer = headers[i].value;
      break;
    }
  }

  return referer;
}

// The core EPR functionality implemented prior to requests going out (onBeforeSendHeaders)
function regulator(details) {
  var urlProtocol, urlHostname, urlPathname, urlSearch, urlHash;
  var retVal = false;
  var referer;
  var matchedStoredManifest;
  var bailOnRegulation;

  pathAnchor.href = details.url;
  urlProtocol = pathAnchor.protocol;
  urlHostname = pathAnchor.hostname;
  urlPathname = pathAnchor.pathname;
  urlSearch = pathAnchor.search;
  urlHash = pathAnchor.hash;

  bailOnRegulation = false;

  // Bail immediately if this is a manifest request
  if (details.method === "GET" && urlPathname === "/epr-manifest.json" && urlSearch.length == 0 && urlHash.length == 0)
  {
    return {cancel: false};
  }

  // If there's a referer and it matches the domain then we can bail on regulation
  //  ...though continue to download the manifest as necessary
  referer = getReferer(details.requestHeaders);

  if (referer) {
    // Keep track of the referer because it will be necessary in processing responses
    refererTracking[details.requestId] = referer;

    // If the referer scheme / domain matches the request, bail on regulation
    pathAnchor.href = referer;
    if ((pathAnchor.protocol == urlProtocol) && (pathAnchor.hostname == urlHostname)) {
      bailOnRegulation = true;
    }
  }
  else
  {
    bailOnRegulation = noRefererCheck(details, urlSearch, urlHash);
  }

  matchedStoredManifest = false;
  for (var i = 0; i < eprData.manifests.length; i++)
  {
    if (retVal) break;

    pathAnchor.href = eprData.manifests[i].site;
    if ((pathAnchor.protocol != urlProtocol) || (pathAnchor.hostname != urlHostname)) continue;

    matchedStoredManifest = true;

    if (bailOnRegulation) continue;

    // Check against the found manifest, unless it's a stub entry intended to just prevent further download attempts
    if (!eprData.manifests[i].sessionIgnore)
    {
      retVal = checkManifests(i, details.type, urlPathname, urlSearch, urlHash, details.method);
    }

    // TODO: If we block due to a manifest, do a sync re-download and re-evaluation of the manifest
    //       The logic being that we'd block anyway, so performance is not a big deal.
    //       But the driving factor is to allow fixes for broken manifests that would otherwise sit in the cache,
    //        keeping the site broken for some visitors.
    //       Maybe also provide an flag in the manifest to disable this behavior
  }

  return {cancel: retVal};
}

// There is no referer...  Should we bail on regulation?
function noRefererCheck(details, urlSearch, urlHash) {
  //  Could we have a no-querystring/hash top-level navigation?  We want that to bypass regulation too as it's likely a URL typed
  //  directly into the omnibox
  if ((details.method === "GET") && (details.type === "main_frame") && (details.frameId == 0) && (details.parentFrameId == -1) &&
      (urlSearch.length == 0) && (urlHash.length == 0))
  {
    // console.log(details.url + ": " + details.frameId + ": " + details.parentFrameId + ": " + details.tabId);

    // Bail on regulation
    return true;
  }

  // Also bail if it matches existing bookmark (+ no referer + HTTP GET + top-level nav)
  if ((details.method === "GET") && (details.type === "main_frame") && (details.frameId == 0) && (details.parentFrameId == -1) &&
      (bookmarkUrls.indexOf(details.url) != -1))
  {
    return true;
  }

  return false;
}

// Actually do the validation against the appropriate manifest
function checkManifests(i, detailsType, urlPathname, urlSearch, urlHash, urlMethod) {
  var typeCheck, regexRule;
  var re, reMatches;
  var retVal = true;  // Block

  for (var j = 0; j < eprData.manifests[i].rules.length; j++)
  {
    // Check the type of the reference
    //  Do this first to avoid an unnecessary evaluation of the regular expression
    typeCheck = false;
    switch(detailsType) {
      case "main_frame":
      case "sub_frame":
        if (eprData.manifests[i].rules[j].types.indexOf("navigation") != -1) typeCheck = true;
        break;
      case "image":
        if (eprData.manifests[i].rules[j].types.indexOf("image") != -1) typeCheck = true;
        break;
      case "script":
        if (eprData.manifests[i].rules[j].types.indexOf("script") != -1) typeCheck = true;
        break;
      case "stylesheet":
        if (eprData.manifests[i].rules[j].types.indexOf("stylesheet") != -1) typeCheck = true;
        break;
      case "xmlhttprequest":
        if (eprData.manifests[i].rules[j].types.indexOf("xhr") != -1) typeCheck = true;
        break;
      case "object":
      case "other":
        if (eprData.manifests[i].rules[j].types.indexOf("other") != -1) typeCheck = true;
        break;
    }
    if (!typeCheck) continue;

    // Now also short-circuit if the rule says no data is allowed but there is data
    //  If it's not a GET request, just assume it's a POST and thus has data
    if (!eprData.manifests[i].rules[j].allowData)
    {
      if ((urlSearch.length > 1) || (urlHash.length > 1) || (urlMethod != "GET")) continue;
    }

    if (typeof(eprData.manifests[i].rules[j].path) != "undefined" /* String */)
    {
       if (eprData.manifests[i].rules[j].path === urlPathname)
       {
         retVal = false;
         break;
       }
    }
    else if (typeof(eprData.manifests[i].rules[j].regex) != "undefined" /* Regex */)
    {
      regexRule = eprData.manifests[i].rules[j].regex;

      // Set a bit to flag ReDoS
      localStorage["ReDoS-regex"] = regexRule;
      localStorage["ReDoS-path"] = urlPathname;
      localStorage["ReDoS-flag"] = pathAnchor.protocol + "//" + pathAnchor.hostname;

      // Would have been nice to just store regex's as JS regex objects, but JSON doesn't handle that type
      re = new RegExp(regexRule);
      reMatches = urlPathname.match(re);

      localStorage.removeItem("ReDoS-flag");
      localStorage.removeItem("ReDoS-path");
      localStorage.removeItem("ReDoS-regex");

      if (reMatches != null)
      {
        retVal = false;
        break;
      }
    }
  }

  return retVal;
}

// Bookmarked URLs are exempt from EPR
function grovelBookmarks(results) {
  var i;

  for (i = 0; i < results.length; i++)
  {
    try {
      bookmarkUrls.push(results[i].url);
    } catch (e) { }
    try {
      grovelBookmarks(results[i].children);
    } catch (e) { }
  }
}

// Adaptation of http://www.html5rocks.com/en/tutorials/indexeddb/todo/
function configStorage()
{
  EPRStorage.indexedDB.db = null;

  EPRStorage.indexedDB.open = function() {
    var version = 1;
    var request = indexedDB.open("manifests", version);

    request.onupgradeneeded = function(e) {
      var db = e.target.result;

      e.target.transaction.onerror = EPRStorage.indexedDB.onerror;

      if(db.objectStoreNames.contains("manifest")) {
        db.deleteObjectStore("manifest");
      }

      var store = db.createObjectStore("manifest",
        {keyPath: "timeStamp"});
    };

    request.onsuccess = function(e) {
      EPRStorage.indexedDB.db = e.target.result;
      EPRStorage.indexedDB.getAllManifests();
    };

    request.onerror = EPRStorage.indexedDB.onerror;
  }

  EPRStorage.indexedDB.addManifest = function(manifestText) {
    var db = EPRStorage.indexedDB.db;
    var trans = db.transaction(["manifest"], "readwrite");
    var store = trans.objectStore("manifest");
    var request = store.put({
      "text": manifestText,
      "timeStamp" : new Date().getTime()
    });

    request.onsuccess = function(e) {
      // EPRStorage.indexedDB.getAllManifests();
    };

    request.onerror = function(e) {
      console.log(e.value);
    };
  };

  EPRStorage.indexedDB.getAllManifests = function() {
    var db = EPRStorage.indexedDB.db;
    var trans = db.transaction(["manifest"], "readwrite");
    var store = trans.objectStore("manifest");

    var keyRange = IDBKeyRange.lowerBound(0);
    var cursorRequest = store.openCursor(keyRange);

    cursorRequest.onsuccess = function(e) {
      var result = e.target.result;
      if (!!result == false)
      {
        // If indexedDB is blank, initialize it with the static manifest data
        //  and write it back out to indexedDB
        if (eprData.manifests.length == 0) {
          eprData.manifests = eprDataStatic.manifests;
          for (var i = 0; i < eprData.manifests.length; i++)
          {
            EPRStorage.indexedDB.addManifest( JSON.stringify(eprData.manifests[i]) );
          }
        }
        return;
      }

      eprData.manifests.push( JSON.parse(result.value.text) );
      result.continue();
    };

    cursorRequest.onerror = EPRStorage.indexedDB.onerror;
  };

  EPRStorage.indexedDB.deleteManifest = function(id) {
    var db = EPRStorage.indexedDB.db;
    var trans = db.transation(["manifest"], "readwrite");
    var store = trans.objectStore("manifest");

    var request = store.delete(id);

    request.onsuccess = function(e) {

    };

    request.onerror = function(e) {
      console.log(e);
    };
  };

  // Uncomment to temporarily clear IndexedDB
  // indexedDB.deleteDatabase("manifests");
  // This can also be done from the F12 debugger UI

  // Open the db and get all the manifests
  EPRStorage.indexedDB.open();
}

// Operates on responses that come in to check for and handle X-EPR header
function lateRegulator(details) {
  var urlProtocol, urlHostname, urlPathname, urlSearch, urlHash;
  var retVal = false;
  var matchedStoredManifest;
  var xhr;
  var contentType;
  var receivedManifest, receivedManifestPos, failedParse;
  var bailOnRegulation;
  var sawEPRHeader = false;

  pathAnchor.href = details.url;
  urlProtocol = pathAnchor.protocol;
  urlHostname = pathAnchor.hostname;
  urlPathname = pathAnchor.pathname;
  urlSearch = pathAnchor.search;
  urlHash = pathAnchor.hash;

  // Bail immediately if this is a manifest request
  if (details.method === "GET" && urlPathname === "/epr-manifest.json" && urlSearch.length == 0 && urlHash.length == 0)
  {
    return {};
  }

  for (var j = 0; j < details.responseHeaders.length; j++) {
    // Don't let multiple x-epr headers function
    if (sawEPRHeader) break;

    if ((details.responseHeaders[j].name.toLowerCase() === 'x-epr')) {
      if ((details.responseHeaders[j].value.charAt(0) === '1')) {
        // Now we know X-EPR is on the response.  Go download and evaluate the manifest as necessary.
        sawEPRHeader = true;

        if (refererTracking[details.requestId]) {
          // If the referer scheme / domain matches the request, bail on regulation
          pathAnchor.href = refererTracking[details.requestId];
          if ((pathAnchor.protocol == urlProtocol) && (pathAnchor.hostname == urlHostname)) {
            bailOnRegulation = true;
          }
        }
        else
        {
          bailOnRegulation = noRefererCheck(details, urlSearch, urlHash);
        }

        // We do actually need to validate the manifest here, to cover the case where a request is initiated before
        //  there was a manifest (no validation), but by the time we get the response there is already a manifest
        //  (no manifest fetch).
        matchedStoredManifest = false;
        for (var i = 0; i < eprData.manifests.length; i++)
        {
          if (retVal) break;

          pathAnchor.href = eprData.manifests[i].site;
          if ((pathAnchor.protocol != urlProtocol) || (pathAnchor.hostname != urlHostname)) continue;

          matchedStoredManifest = true;

          if (bailOnRegulation) continue;

          if (!eprData.manifests[i].sessionIgnore)
          {
            retVal = checkManifests(i, details.type, urlPathname, urlSearch, urlHash, details.method);
          }
        }

        // We didn't match an existing manifest.  Try to fetch one if necessary.
        if (!matchedStoredManifest)
        {
          // Do a sync fetch
          //  XSS on navigation can happen immediately, doesn't require the user to first auth to the site as with XSRF
          // Previously we were doing async fetches when XSS wasn't a concern, but it turns out XHR can hang in the
          //  case where a sync request for a URL is made when an async request for the same URL is pending.  It's
          //  also just a wierd situation when an async request goes out but then a secondary sync request went out
          //  for the same URL.
          // Anyway, going 100% synchronous eliminates the problems, reduces code complexity, and is reasonable given
          //  that a manifest fetch is a rare operation.
          console.log("Making sync manifest req for: " + details.url);
          xhr = new XMLHttpRequest();

          xhr.open("GET", urlProtocol + "//" + urlHostname + "/epr-manifest.json", false);

          try {
            xhr.send(null);
          } catch (e)
          {
            console.log("Sync xhr error on manifest req for " + details.url);
          }

          // Validate the response is of the right type and of a reasonable size
          contentType = xhr.getResponseHeader("Content-Type");
          if ((xhr.status === 200) && contentType && (contentType.indexOf("application/json") == 0)
              && (xhr.responseText.length < 5242880))
          {
            failedParse = false;
            try {
              receivedManifest = JSON.parse(xhr.responseText);
            } catch (e) {
              failedParse = true;
            }

            if (!failedParse)
            {
              // Don't let a manifest specify what site it's for, override the site
              receivedManifest.site = urlProtocol + "//" + urlHostname;

              receivedManifestPos = eprData.manifests.push(receivedManifest) - 1;
              if (!bailOnRegulation)
              {
                retVal = checkManifests(receivedManifestPos, details.type, urlPathname, urlSearch, urlHash, details.method);
              }

              // Need to re-serialize the manifest if only because we changed the site
              //  Then persist it in indexedDB
              EPRStorage.indexedDB.addManifest(JSON.stringify(receivedManifest));
            }
          }
          else
          {
            // Push a manifest entry that prevents more manifest fetch attempts for the duration of this browsing session, for this host
            //  If the JSON fails to parse then we still won't get here, but no big deal
            eprData.manifests.push( { "site": urlProtocol + "//" + urlHostname, "sessionIgnore": true } );
          }
        }
      }
    }
  }

  // It's possible that we downloaded an evaluated a manifest, and it tells us to block the request
  // But at this point we already made the request.  All we can do is block the response from being shown
  // This prevents XSS but not XSRF.  That's fine though because with XSRF, you'd need to go authenticate
  //  to the site at some earlier point, and a manifest would have been fetched at that point, allowing
  //  the request to have been blocked before it even went out (in onBeforeSendHeaders).
  if (retVal) {
    return { redirectUrl: "data:text/plain;charset=utf-8,%23" };
  }
  else {
    return { };
  }

}

function deleteReferer(details) {
  // Just delete the referer as it's no longer necessary to track
  try {
    delete refererTracking[details.requestId];
  } catch (e) {};
}

pathAnchor = document.createElement('a');

bootWorker();

var EPRStorage = {};
EPRStorage.indexedDB = {};
configStorage();

bookmarkUrls = new Array();
chrome.bookmarks.getTree(grovelBookmarks);

chrome.webRequest.onBeforeSendHeaders.addListener(regulator, {urls: ["<all_urls>"]}, ["blocking", "requestHeaders"]);
chrome.webRequest.onHeadersReceived.addListener(lateRegulator, {urls: ["<all_urls>"]}, ["blocking", "responseHeaders"]);
chrome.webRequest.onCompleted.addListener(deleteReferer, {urls: ["<all_urls>"]});
