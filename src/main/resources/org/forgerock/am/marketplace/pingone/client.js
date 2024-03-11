/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

var body = document.body;
var script = document.createElement('script');
script.type = 'text/javascript';
script.src = "${theUrl}";
script.setAttribute('defer', 'defer');

if (typeof window._pingOneSignals === 'function') {
  document.getElementById('loginButton_0').click()
} 
else {
  document.body.appendChild(script);
  Array.prototype.slice.call(document.getElementsByTagName('button')).forEach(function (e) {
    e.style.display = 'none'
  })
  function onPingOneSignalsReady(callback) {
    if (window['_pingOneSignalsReady']) {
      callback();
    } else {
      document.addEventListener('PingOneSignalsReadyEvent', callback);
    }
  }

  onPingOneSignalsReady(function () {
    _pingOneSignals.init({
      behavioralDataCollection: JSON.parse("${behavioralDataCollection}"),
      envId: "${envId}",
      consoleLogEnabled: JSON.parse("${consoleLogEnabled}"),
      lazyMetadata: JSON.parse("${lazyMetadata}"),
      deviceKeyRsyncIntervals: JSON.parse("${deviceKeyRsyncIntervals}"),
      enableTrust: JSON.parse("${enableTrust}"),
      disableTags: JSON.parse("${disableTags}"),
      disableHub: JSON.parse("${disableHub}")
    }).then(function () {
      console.log("PingOne Signals initialized successfully");
      document.getElementById('loginButton_0').click()
    }).catch(function (e) {
      console.error("SDK Init failed", e);
    });
  })
}