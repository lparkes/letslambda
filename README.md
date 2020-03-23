# LetsLambda Simplified Fork #
This is a fork of kiddouk/letslambda that has been simplified
and updated to work with letsencrypt version 2 API.

This fork has the benefit of not requring any kind of build process other than pip install. 

It replaces the ACME dependencies with the SEWER letsencrypt library from: https://github.com/komuw/sewer

It has only been tested with Route53 and does not save to IAM or ELB as the original does. These functions have been removed as Amazon Certificate Manager (ACM) seems to be better for those cases. This library is intended for the case where SSL offloading has to happen on the EC2 instance, e.g. mutual TLS. ACM private certificate authority costs around $3k per month so this is a great alternative.