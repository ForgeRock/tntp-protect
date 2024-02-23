var body = document.body;
var script = document.createElement('script');
script.type = 'text/javascript';
script.src = 'url';
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
      behavioralDataCollection: JSON.parse("${behavioralDataCollection}")
    }).then(function () {
      console.log("PingOne Signals initialized successfully");
      document.getElementById('loginButton_0').click()
    }).catch(function (e) {
      console.error("SDK Init failed", e);
    });
  })
}