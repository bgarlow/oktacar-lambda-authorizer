# Lambda Authorizer for AWS API Gateway using [Okta's jwt-verifier for Node]('https://github.com/okta/okta-oidc-js/tree/master/packages/jwt-verifier')

This project is sample implementation of an AWS Lambda custom authorizer for [AWS API Gateway](https://aws.amazon.com/api-gateway/) that works with a JWT bearer token (`access_token`) issued by an OAuth 2.0 Authorization Server.  It can be used to secure access to APIs managed by [AWS API Gateway](https://aws.amazon.com/api-gateway/).

## Use Case
This authorize was built as a demo tool to show how to secure an API resource on AWS API Gateway using OAuth 2.0. The authorizer is specifically designed to work with [mock_api_lambda](https://github.com/bgarlow/mock_api_lambda), a Lambda Function that serves as a mock API endpoint. The authorizer adds data about the policy decision (success and failure) to the context object of it's response to the API Gateway. The mock_api_lambda function, in turn, returns that contextual information in it's response. 

### Scopes

The authorizer uses a simple json mapping object to define which scopes are required for each API resource/HTTP method. A scope is mapped to an HTTP method/resource pair (an endpoint). This can be a 1:1 mapping, or several scopes could be required for a single method/resource as shown below. 

The authorizer will loop through the scopes in the mapping json object, comparing them with the scopes present in the bearer token. When a match is found, the method/resource is added to the policy document as an explicit allow. If a scope in the scope mapping JSON is not present in the bearer token, the access policy explicitly deny access to the method/resource, and add an error message to the `authorizerMessage` attribute of policy document's context indicating which scope(s) were missing. The `authorizerMessage` is used to provide more informative (demo purposes only) error message from the API Gateway. Here's a sample scope->method/resource mapping, where the scope fab:read is required to access the /banks resource via GET. 

```javascript
const scpMapping = {
  'fab:read': {
      method: 'GET',
      resource: '/banks'
  },
  'banks:read': {
      method: 'GET',
      resource: '/banks'
  }
};
````

### Context Object and Messages

To use the messages returned in the `authorizerMessage` attribute, you'll need to modify the API's Gateway Response messages. I modified Default 4XX, and the 403 responses like this:
```json
{
    "[Default 4XX] message": $context.error.messageString,
    "Authorizer Message": "$context.authorizer.authorizerMessage"
}
```

Where `$context.authorizer.authorizerMessage` is the `authorizerMessage` attribute returned on the policy document context object.

### Environment Variables (.env)

Update the `ISSUER` and `AUDIENCE` variables in the `.env` file

```
ISSUER=https://example.oktapreview.com/oauth2/aus8o56xh1qncrlwT0h7
AUDIENCE=https://api.example.com
```

It is critical that the `issuer` and `audience` claims for JWT bearer tokens are [properly validated using best practices](http://www.cloudidentity.com/blog/2014/03/03/principles-of-token-validation/).  You can obtain these values from your OAuth 2.0 Authorization Server configuration.

The `audience` value should uniquely identify your AWS API Gateway deployment.  You should assign unique audiences for each API Gateway authorizer instance so that a token intended for one gateway is not valid for another.

# Deployment

### Install Dependencies

Run `npm install` to download all of the authorizer's dependent modules. This is a prerequisite for deployment as AWS Lambda requires these files to be included in the uploaded bundle.

### Create Bundle

Run `npm run bundle`. This will create custom-authorizer.zip with all the source, configuration and node modules AWS Lambda needs.

### Test your endpoint remotely

#### With Postman

You can use Postman to test the REST API

* Method: < matching the Method in API Gateway >
* URL `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<resource>`
 * The base URL you can see in the Stages section of the API
 * Append the Resource name to get the full URL
* Header - add an Authorization key
 * Authorization : Bearer <token>

#### With curl from the command line

    $ curl -X POST <url> -H 'Authorization: Bearer <token>'

#### In (modern) browsers console with fetch

    fetch( '<url>', { method: 'POST', headers: { Authorization : 'Bearer <token>' }}).then(response => { console.log( response );});
