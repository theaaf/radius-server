# radius-server

This is a simple RADIUS server, written in Go.

## Useful dev commands

* `docker-compose up --build radius-test`
* `docker-compose run radius-server add-identity --name user --password password --redis redis:6379`
* `radtest -4 -t eap-md5 -x 'user' 'password' 127.0.0.1 10 'secret'`

`eapol_test` from [wpa_supplicant](http://w1.fi/wpa_supplicant/) is also useful for testing.

## Deployment

The deployment is mostly done via CloudFormation (see cloudformation.yaml). There are a few exceptions though:

* The VPC itself was not created via CloudFormation.
* The ECR repo was not created via CloudFormation.
* The RADIUS service was not created via CloudFormation. It should be added as soon as CloudFormation supports ECS service discovery. Until then, the service must be updated manually on each deployment of a new Docker image.

## Caution

This server has not undergone extensive peer review and should not be blindly trusted.
