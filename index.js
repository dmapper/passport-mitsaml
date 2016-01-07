"use strict;"

/*
    MIT SAML Passport Authentication Module
*/

const saml = require('passport-saml');
const util = require('util');

const idPCert = 'MIIDCDCCAfCgAwIBAgIJAK/yS5ltGi7MMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNVBAMTC2lkcC5taXQuZWR1MB4XDTEyMDczMDIxNTAxN1oXDTMyMDcyNTIxNTAxN1owFjEUMBIGA1UEAxMLaWRwLm1pdC5lZHUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgC5Y2mM/VMThzTWrZ2uyv3Gw0mWU9NgQpWN1HQ/lLBxH1H6pMc5+fGpOdrvxH/Nepdg6uAJwZrclTDAHHpG/THb7K063NRtic8h9UYSqwxIWUCXI8qNijcWA2bW6PFEy4yIP611J+IzQxzD/ZiR+89ouzdjNBrPHzoaIoMwflftYnFc4L/qu4DxE/NWgANYPGEJfWUFTVpfNV1Iet60904zl+O7T79mwaQwwOMUWwk/DEQyvG6bf2uWL4aFx4laBOekrA+5rSHUXAFlhCreTnzZMkVoxSGqYlc5uZuZmpFCXZn+tNpsVYz+c4Hve3WOZwhx/7bMGCwlx7oovoQWQ5AgMBAAGjWTBXMDYGA1UdEQQvMC2CC2lkcC5taXQuZWR1hh5odHRwczovL2lkcC5taXQuZWR1L3NoaWJib2xldGgwHQYDVR0OBBYEFF5aINzhvMR+pOijYHtr3yCKsrMSMA0GCSqGSIb3DQEBBQUAA4IBAQDfVpscchXXa4Al/l9NGNwQ1shpQ8d+k+NpX2Q976jau9DhVHa42F8bfl1EeHLMFlN79aUxFZb3wvr0h5pq3a8F9aWHyKe+0R10ikVueDcAmg0V7MWthFdsyMwHPbnCdSXo2wh0GhjeIF3f3+hZZwrZ4sZqjX2RmsYnyXgS1r5mzuu4W447Q1fbC5BeZTefUhJcfHQ56ztIFtLJdRuHHnqj09CaQVMD1FtovM86vYwVMwMsgOgkN3c7tW6kXHHBHeEA31xUJsqXGTRlwMSyJTju3SFvhXI/8ZIxshTzWURBo+vf6A6QQvSvJAju4zVLZy83YB/cvAFsV3BexZ4xzuQD';

// entityID="https://idp.mit.edu/shibboleth"

const idPEntryPoint = 'https://idp.mit.edu/idp/profile/SAML2/Redirect/SSO';

const urls = {
    metadata: '/MitSaml.sso/Metadata'
};

//export the urls map
module.exports.urls = urls;

//map of possible profile attributes and what name
//we should give them on the resulting user object
//add to this with other attrs if you request them
const profileAttrs = {
    'urn:oid:0.9.2342.19200300.100.1.3': 'email',
    'urn:oid:2.5.4.4': 'lastname',
    'urn:oid:2.5.4.42': 'firstname',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'principalName'
};



/*
    Passport Strategy for CMU Shibboleth Authentication
    This class extends passport-saml's Strategy, providing the necessary
    options and handling the conversion of the returned profile into a
    sensible user object.

    options should contain:
        entityId: your server's entity id,
        domain: your server's domain name,
        callbackUrl: login callback url (relative to domain),
        privateKey: your private key for signing requests (optional)
*/

function Strategy(options, verify) {

    var self = this;

    samlOptions = {
        entryPoint: idPEntryPoint,
        cert: idPCert,
        identifierFormat: null,
        issuer: options.entityId || options.domain,
        callbackUrl: 'https://' + options.domain + options.callbackUrl,
        decryptionPvk: options.privateKey,
        privateCert: options.privateKey,
        acceptedClockSkewMs: 180000,
        disableRequestedAuthnContext: true,
        passReqToCallback: true
    };

    function convertProfileToUser(req, profile) {
      var user = {};
      var niceName;
      var attr;
      for (attr in profile) {
        niceName = profileAttrs[attr];
        if (niceName !== undefined && profile[attr]) {
          user[niceName] = profile[attr];
        }
      }

      var email = user.email || user.principalName || '';

      user.id = email;
      user.email = email;

      if (user.firstname && user.lastname) {
        user.name = user.firstname + ' ' + user.lastname;
      }

      user.name = user.name || email.split('@')[0];

      user.provider = self.name;

      return user;
    }

    function _verify(req, profile, done) {

      if (!profile)
        return done(new Error('Empty SAML profile returned!'));
      else
        profile = convertProfileToUser(req, profile);

      if (!verify) return done(null, profile);

      if (options.passReqToCallback) {
        verify(req, undefined, undefined, profile, done);
      } else {
        verify(undefined, undefined, profile, done);
      }
    }

    saml.Strategy.call(this, samlOptions, _verify);

    this.name = options.name || 'mitsaml';
}

util.inherits(Strategy, saml.Strategy);

//expose the Strategy
module.exports.Strategy = Strategy;

/*
    Route implementation for the standard Shibboleth metadata route
    usage:
        var mitsaml = require(...);
        var strategy = new mitsaml.Strategy({...});
        app.get(mitsaml.urls.metadata, mitsaml.metadataRoute(strategy, myPublicCert));
*/

module.exports.metadataRoute = function(strategy, publicCert) {
    return function(req, res) {
        res.type('application/xml');
        res.status(200).send(strategy.generateServiceProviderMetadata(publicCert));
    }
};

/*
    Middleware for ensuring that the user has authenticated.
    You can use this in two different ways. If you pass this to
    app.use(), it will secure all routes added after that.
    Or you can use it selectively on routes that require authentication
    like so:
        app.get('/foo/bar', ensureAuth(loginUrl), function(req, res) {
            //route implementation
        });

    where loginUrl is the url to your login route where you call
    passport.authenticate()
*/
module.exports.ensureAuth = function(loginUrl) {
    return function(req, res, next) {
        if (req.isAuthenticated())
            return next();
        else {
            req.session.authRedirectUrl = req.url;
            res.redirect(loginUrl);
        }
    }
};

/*
    Middleware for redirecting back to the originally requested URL after
    a successful authentication. The ensureAuth() middleware above will
    capture the current URL in session state, and when your callback route
    is called, you can use this to get back to the originally-requested URL.
    usage:
        var mitsaml = require(...);
        var strategy = new mitsaml.Strategy({...});
        app.get('/login', passport.authenticate(strategy.name));
        app.post('/login/callback', passport.authenticate(strategy.name), mitsaml.backtoUrl());
        app.use(mitsaml.ensureAuth('/login'));
*/
module.exports.backToUrl = function(defaultUrl) {
    return function(req, res) {
        var url = req.session.authRedirectUrl;
        delete req.session.authRedirectUrl;
        res.redirect(url || defaultUrl || '/');
    }
};



