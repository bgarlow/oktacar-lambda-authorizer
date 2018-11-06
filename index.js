require('dotenv').config();
const AuthPolicy = require('./auth-policy');
const OktaJwtVerifier = require('@okta/jwt-verifier');
const issuer = process.env.ISSUER;
const audience = process.env.AUDIENCE;
const clientId = process.env.CLIENT_ID;
const oktaAccessTokenVerifier = new OktaJwtVerifier({
    issuer: issuer,
    clientId: clientId
});

/**
 *
 * Define a mapping between the scopes present in the access token and API method + resource.
 * The mapping will be used to generate a policy document allowing the appropriate API endpoints for the
 *  access token provided.
 *
  */
const scpMapping = {
  'fileshare.teamshare.list': {
      method: 'GET',
      resource: '/teamshare'
  }
};

let authorizerMessage;

//Bind prefix to log levels
console.log = console.log.bind(null, '[LOG]');
console.info = console.info.bind(null, '[INFO]');
console.warn = console.warn.bind(null, '[WARN]');
console.error = console.error.bind(null, '[ERROR]');

/**
 * Build a policy document to allow the appropriate method + resource endpoints on the API, based
 *  on the method/resource/scope mapping defined in scpMapping above. Note that the HEAD and OPTIONS
 *  methods are allowed on all endpoints.
 * @param claims
 * @param awsAccountId
 * @param apiOptions
 * @param resource
 * @param pathParam
 * @returns {AuthPolicy}
 */
const buildPolicyDocument = (claims, awsAccountId, apiOptions, resource, pathParam, denyAll) => {

    let principal = (claims && claims.sub) ? claims.sub : 'user';
    let policy = new AuthPolicy(principal, awsAccountId, apiOptions);
    let scopedResource;
    const scopes = Object.keys(scpMapping);

    authorizerMessage = '';

    // If the jwtTokenHandler token validation fails for any reason, we'll call buildPolicyDocument with denyAll = true.
    // We'll build a policy document denying all methods, to which we can append a context object that can contain
    // an attribute-value pair with the actual error message returned from jwtTokenHandler. This is only for demo purposes,
    //  to allow us to see the authorizer results in Postman rather than digging around in the CloudWatch logs.
    if (denyAll) {
        policy.denyAllMethods(resource);
    } else {
        // Loop through all of the scopes in the scpMapping JSON defined above.
        for (let scope of scopes) {
            scopedResource = scpMapping[scope].resource;

            // pathParam would represent the UUID parameter the requested resource. We aren't building
            //  our policy document to that granularity, so this isn't used.
            if (pathParam) {
                //console.log(`pathParam: ${pathParam}`);
            }

            // If the scopes claim in the access token contains the current scope, add the corresponding (from scpMapping)
            //  method and resource to the policy document.
            if (claims && claims.scp && claims.scp.includes(scope)) {
                policy.allowMethod(AuthPolicy.HttpVerb[scpMapping[scope].method], scopedResource);
            } else {
                policy.denyMethod(AuthPolicy.HttpVerb[scpMapping[scope].method], scopedResource);
                authorizerMessage += `Explicitly Deny ${AuthPolicy.HttpVerb[scpMapping[scope].method]} ${scopedResource} missing scope: ${scope}`;
            }

        }

        // Allow HEAD and OPTIONS for the explicitly requested resource
        policy.allowMethod(AuthPolicy.HttpVerb.HEAD, resource);
        policy.allowMethod(AuthPolicy.HttpVerb.OPTIONS, resource);
    }

    return policy;
};

/**
 * The handler for our lambda authorizer
 * @param event
 * @param context
 */
exports.handler = function (event, context, callback) {

    const input = {
        event: event,
        context: context
    };


    // decompose the event object's methodArn to extract details needed for token validation.
    let apiOptions = {};
    const arnParts = event.methodArn.split(':');
    const apiGatewayArnPart = arnParts[5].split('/');
    const awsAccountId = arnParts[4];
    apiOptions.region = arnParts[3];
    apiOptions.restApiId = apiGatewayArnPart[0];
    apiOptions.stage = apiGatewayArnPart[1];
    const method = apiGatewayArnPart[2];
    let resource = '/'; // root resource
    let claims;

    if (apiGatewayArnPart[3]) {
        resource += apiGatewayArnPart[3];
    }

    let pathParam = undefined;

    if (apiGatewayArnPart[4]) {
        pathParam = apiGatewayArnPart[4];
        console.log(`pathParam: ${pathParam}`);
    }

    // used for demo display purposes only
    const methodArnJson = {
        awsAccountId: awsAccountId,
        region: apiOptions.region,
        restApiId: apiOptions.restApiId,
        stage: apiOptions.stage,
        method: method,
        resource: resource,
        id: pathParam
    };


    console.log(`event.authorizationToken follows...`);
    console.log(event.authorizationToken);

    accessToken = event.authorizationToken.split(' ')[1];
    console.log(accessToken);

    oktaAccessTokenVerifier.verifyAccessToken(accessToken)
        .then(jwt => {
            // the token is valid
            claims = jwt.claims;
            console.log(`tokenClaims follows...`);
            console.log(claims);

            let policy = buildPolicyDocument(claims, awsAccountId, apiOptions, resource, pathParam, false);

            const scopes = (claims && claims.scp) ? claims.scp.join(' ') : null;

            let policyDoc = policy.build();

            // Pack the authorizer context with some useful info that can be referenced by the API
            const authorizerResponseContext = {
                issuer: issuer,
                audience: audience,
                //jwks: jwks.toString(),
                claims: JSON.stringify(claims),
                awsAccountId: awsAccountId,
                region: apiOptions.region,
                restApiId: apiOptions.restApiId,
                state: apiOptions.stage,
                scopes: scopes,
                method: method,
                apiResource: resource,
                pathParam: pathParam,
                principalId: policyDoc.principalId,
                version: policyDoc.policyDocument.Version,
                action: policyDoc.policyDocument.Statement[0].Action,
                effect: policyDoc.policyDocument.Statement[0].Effect,
                resource: policyDoc.policyDocument.Statement[0].Resource.join(" "),
                authorizerMessage: authorizerMessage
            };

            policyDoc.context = authorizerResponseContext;

            console.log(`policyDoc follows...`);
            console.log(JSON.stringify(policyDoc));

            callback(null, policyDoc);
        })
        .catch(err => {
            console.log(`Error in jwtTokenHandler.verifyRequest follows...`);
            console.log(err);

            let policy = buildPolicyDocument(claims, awsAccountId, apiOptions, resource, pathParam, true);
            let policyDoc = policy.build();

            const errString = err.toString();
            policyDoc.context = {
                authorizerMessage: errString
            };

            console.log(`Failed to validate bearer token: ${errString}`);

            // In order for AWS Gateway to return a generic 401 response, you have to send 'Unauthorized' to the callback.
            // We want to return the policy document along with the context object so that we can see what actually failed,
            // so we'll be getting 403 Access Denied. The API gateway's response message for 403 Access Denied has been edited
            // to show the err value populated above.
            //return callback('Unauthorized');

            console.log(`Error Condition: policyDoc follows...`);
            console.log(JSON.stringify(policyDoc));
            callback(null, policyDoc);
        });

};
