#!/bin/bash

printf "Enter which cloud you like to login: (AWS, GCLOUD, AZURE)\n"
read cloud

printf "Account ID: \n"
read account_id


if [$cloud = "AWS"]
then
    printf "MFA users ARN: \n"
    read mfa_arn
fi