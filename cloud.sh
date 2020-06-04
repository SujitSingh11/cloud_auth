#!/bin/bash

printf "Enter which cloud you like to login: (AWS, GCLOUD, AZURE)\n"
read cloud



if [$cloud = "AWS"]
then
    printf "Account ID: \n"
    read account_id

    printf "MFA users ARN: \n"
    read mfa_arn

    python console.py $cloud $account_id $mfa_arn
fi


if [$cloud = "GCLOUD"]
then
    printf "GOOGLE APPLICATION CREDENTIALS: \n"
    read gac

    python console.py $cloud $gac
fi