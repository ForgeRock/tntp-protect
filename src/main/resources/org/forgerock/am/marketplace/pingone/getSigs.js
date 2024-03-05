_pingOneSignals.getData().then(function (result) {
  setTimeout(function () {
    document.getElementById('clientScriptOutputData').value = result
    document.getElementById('loginButton_0').click();
  }, 500)
}).catch(function (e) {
  console.error("SDK retrieve failed", e);
})
