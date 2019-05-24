import { IDP_SSO, SP_VERIFY } from "./constants";
import { getPath, getReqUrl } from "../utils";
import assignIn from "lodash.assignin";
import SessionParticipants from "samlp/lib/sessionParticipants";
import samlp from "samlp";
import { SAML, samlp as _samlp } from "passport-wsfed-saml2";
import { SAMLUser, VetsAPIClient } from '../VetsAPIClient';
import * as url from "url";
import {
  buildPassportLoginHandler,
  testLevelOfAssuranceOrRedirect,
  loadICN,
  scrubUserClaims,
  serializeAssertions,
} from './acsHandlers';

export const getHashCode = (str) => {
  var hash = 0;
  var i = 0;
  if (str.length == 0) return hash;
  for (i = 0; i < str.length; i++) {
    var char = str.charCodeAt(i);
    hash = ((hash<<5)-hash)+char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash;
};

export const samlLogin = function(template) {
  return function(req, res, next) {
    const acsUrl = req.query.acsUrl ?
          getReqUrl(req, req.query.acsUrl) :
          getReqUrl(req, req.sp.options.requestAcsUrl);
    const authnRequest = req.authnRequest ? req.authnRequest : req.session.authnRequest;
    req.authnRequest = authnRequest;
    const samlp = new _samlp(req.sp.options.getResponseParams(), new SAML.SAML(req.sp.options.getResponseParams()));

    [
      ['id_me_login_link', 'http://idmanagement.gov/ns/assurance/loa/3'],
      ['dslogon_login_link', 'dslogon'],
      ['mhv_login_link', 'myhealthevet'],
      ['id_me_signup_link', 'http://idmanagement.gov/ns/assurance/loa/3', '&op=signup']
    ].reduce((memo, [key, authnContext, exParams = null]) => {
      const params = req.sp.options.getAuthnRequestParams(
        acsUrl,
        req.query.forceauthn === '' || req.query.forceAuthn === '' || req.query.forceauthn || req.query.forceAuthn,
        (req.authnRequest && req.authnRequest.relayState) || '/',
        authnContext
      );
      return memo.then((m) => {
        return new Promise((resolve, reject) => {
          samlp.getSamlRequestUrl(params, (err, url) => {
            if (err) {
              reject(err);
            }

            if (exParams) {
              m[key] = url + exParams;
            } else {
              m[key] = url;
            }
            resolve(m);
          });
        });
      });
    }, Promise.resolve({})).then(
      (authOptions) => res.render(template, authOptions)
    ).catch(next);
  }
};

/**
 * Shared Handlers
 */

export const parseSamlRequest = function(req, res, next) {
  samlp.parseRequest(req, function(err, data) {
    if (err) {
      console.warn("Allowing login with no final redirect.");
      next();
    };
    if (data) {
      req.authnRequest = {
        relayState: req.query.RelayState || req.body.RelayState,
        id: data.id,
        issuer: data.issuer,
        destination: data.destination,
        acsUrl: data.assertionConsumerServiceURL,
        forceAuthn: data.forceAuthn === 'true'
      };
      req.session.authnRequest = req.authnRequest;
    }
    next();
  });
};

export const getSessionIndex = (req) => {
  if (req && req.session) {
    return Math.abs(getHashCode(req.session.id)).toString();
  }
  return 0;
};

export const getParticipant = (req) => {
  const participant = {
    serviceProviderId: req.idp.options.serviceProviderId,
    sessionIndex: getSessionIndex(req),
    serviceProviderLogoutURL: req.idp.options.sloUrl
  };
  if (req.user) {
    participant.nameId = req.user.userName;
    participant.nameIdFormat = req.user.nameIdFormat;
  }
  return participant;
};

export const idpSignIn = function(req, res) {
  const authOptions = extend({}, req.idp.options);
  Object.keys(req.body).forEach(function(key) {
    var buffer;
    if (key === '_authnRequest') {
      buffer = new Buffer(req.body[key], 'base64');
      req.authnRequest = JSON.parse(buffer.toString('utf8'));

      // Apply AuthnRequest Params
      authOptions.inResponseTo = req.authnRequest.id;
      if (req.idp.options.allowRequestAcsUrl && req.authnRequest.acsUrl) {
        authOptions.acsUrl = req.authnRequest.acsUrl;
        authOptions.recipient = req.authnRequest.acsUrl;
        authOptions.destination = req.authnRequest.acsUrl;
        authOptions.forceAuthn = req.authnRequest.forceAuthn;
      }
      if (req.authnRequest.relayState) {
        authOptions.RelayState = req.authnRequest.relayState;
      }
    } else {
      req.user[key] = req.body[key];
    }
  });

  if (!authOptions.encryptAssertion) {
    delete authOptions.encryptionCert;
    delete authOptions.encryptionPublicKey;
  }

  // Set Session Index
  authOptions.sessionIndex = getSessionIndex(req);

  // Keep calm and Single Sign On
  samlp.auth(authOptions)(req, res);
};

const processAcs = (acsUrl) => [
  buildPassportLoginHandler(acsUrl),
  testLevelOfAssuranceOrRedirect,
  loadICN,
  scrubUserClaims,
  serializeAssertions,
];

export const acsFactory = (app, acsUrl) => {
  app.get(
    getPath(acsUrl),
    processAcs(acsUrl)
  );
  app.post(
    getPath(acsUrl),
    processAcs(acsUrl)
  );
};

const setUpSaml = function(req, res, view) {

}