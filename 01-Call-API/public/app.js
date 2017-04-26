$(document).ready(function() {
  var auth = new auth0.WebAuth({
    domain: AUTH0_DOMAIN,
    clientID: AUTH0_CLIENT_ID
   });


    $('.btn-login').click(function(e) {
      e.preventDefault();
      auth.authorize({
        audience: API_AUDIENCE,
        scope: 'openid profile',
        responseType: 'code',
        redirectUri: AUTH0_CALLBACK_URL
      });
    });
});
