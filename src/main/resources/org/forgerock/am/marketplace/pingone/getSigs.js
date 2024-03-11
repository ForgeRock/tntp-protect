/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

_pingOneSignals.getData().then(function (result) {
  setTimeout(function () {
    document.getElementById('clientScriptOutputData').value = result
    document.getElementById('loginButton_0').click();
  }, 500)
}).catch(function (e) {
  console.error("SDK retrieve failed", e);
})
