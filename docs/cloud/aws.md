## Tools 

- <​https://awspolicygen.s3.amazonaws.com/policygen.html>
- <https://github.com/toniblyx/my-arsenal-of-aws-security-tools#offensive>
- <https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools>
- <https://github.com/andresriancho/enumerate-iam>
- Amazon Web Services In Plain English: <https://expeditedsecurity.com/aws-in-plain-english/>
- The AWS exploitation framework, designed for testing the security of Amazon Web Services environments: <https://github.com/RhinoSecurityLabs/pacu>
- Security tool to perform AWS security best practices assessments: <https://github.com/toniblyx/prowler>
- AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized HTML report: <https://github.com/salesforce/cloudsplaining>
- WeirdAAL (AWS Attack Library): <https://github.com/carnal0wnage/weirdAAL>
- barq: The AWS Cloud Post Exploitation framework!: <https://github.com/Voulnet/barq>

## References

- <https://github.com/toniblyx/my-arsenal-of-aws-security-tools>
- <https://anir0y.live/class/blog/securityaudit-aws/>
- Unauthenticated AWS Role Enumeration (IAM Revisited): <https://rhinosecuritylabs.com/aws/aws-role-enumeration-iam-p2/>

## EBS 

- Search exposed EBS volumes for secrets: <https://github.com/BishopFox/dufflebag>
- `You can identify EBS volumes/snapshots owned bya  specific company if you know their AWS account IDs.  Which you may be able to find from other data seepage tecniques, eg. if they leak it in source code, or if you are able to do any recon of any of their other AWS resources that would include the account ID in any ARNs`

## S3

###  New References

- S3 Book: <https://github.com/nagwww/aws-s3-book>
- <https://github.com/mxm0z/awesome-sec-s3>

### Collections

- <https://github.com/nagwww/101-AWS-S3-Hacks>

```
Hack : Add ACL to an Object. Grant Read privilages to the bucket using canonical user id
Hack : Add ACL to an object. Grant Read privilages to the bucket using email address
Hack : Add ACL to the bucket. Grant Read privilages to the bucket using canonical user id
Hack : Add ACL to the bucket. Grant Read privilages to the bucket using email address
Hack : Add a tag to S3 bucket
Hack : Add lifecycle to S3 Folder
Hack : Add lifecycle to S3 bucket
Hack : Add lifecycle to S3 bucket, set the effective date. Don't specify the time or specify GMT midnight
Hack : Add lifecycle to S3 bucket, set the effective days
Hack : Check if a key exists
Hack : Compute MD5 for an S3 object
Hack : Configure this bucket to act as a website
Hack : Convert an existing key in an S3 bucket that uses the STANDARD to RRS
Hack : Copy the current key to a different Bucket
Hack : Copy the current key to a different Bucket with Reduced Redundancy Storage (RRS)
Hack : Create a Bucket in S3
Hack : Create a S3 bucket in a different region EU
Hack : Create a folder in a S3 bucket
Hack : Create a new object in S3
Hack : Delete a S3 bucket
Hack : Delete a s3 object
Hack : Delete all cors for the s3 bucket
Hack : Delete all files in a folder
Hack : Delete lifecycle to S3 bucket
Hack : Delete tags of a S3 bucket
Hack : Disable Logging for the S3 bucket
Hack : Disable a buckets Versioning
Hack : Disable a lifecycle to S3 bucket
Hack : Download a S3 file or a S3 object
Hack : Download a file using the method get_file
Hack : Enable Logging for the S3 bucket
Hack : Enable Versioning
Hack : Find out the status of the Bucket Versioning
Hack : Generate a URL for the S3 bucket with an expiration time 20 seconds
Hack : Generate a URL for the S3 object with expiration of 5 min
Hack : Get CORS for an S3 bucket
Hack : Get CORS for an S3 bucket as xml
Hack : Get a metadata value name 'name' added to the S3 object
Hack : Get all the S3 regions
Hack : Get all the metadata added to the S3 object
Hack : Get all the versions of the S3 Objects
Hack : Get an expiry date of a key/object in S3
Hack : Get lifecycle to S3 bucket
Hack : Get lifecycle to S3 bucket as xml
Hack : Get status of the restore of an object from glacier
Hack : Get the ACL of the S3 bucket
Hack : Get the ACL of the object
Hack : Get the ACL of the object as xml
Hack : Get the Location of the s3 bucket
Hack : Get the bucket Policy
Hack : Get the canonical user id of the S3 bucket
Hack : Get the content type of object. Note only works with get_key
Hack : Get the contents of the object as a string
Hack : Get the get_xml_acl of an S3 object
Hack : Get the redirect for an S3 object
Hack : Get the tags of a S3 bucket
Hack : Get the website configuration for this s3 bucket
Hack : Get the website configuration in xml for this s3 bucket
Hack : Get the website_endpoint of a s3 bucket
Hack : How to add an exception
Hack : How to enable debugging for S3
Hack : List all the S3 buckets
Hack : List all the grants for a given Bucket
Hack : List all the objects Owner
Hack : List all the objects in a S3 bucket
Hack : List all the objects last modified timestamp in Zulu format
Hack : List all the objects size in bytes
Hack : List all the objects with in a bucket
Hack : List all the objects with in a bucket and if the object is moved to Glacier
Hack : List all the objects with in a bucket with a prefix
Hack : List all the objects with the versions for a given Bucket
Hack : List whether the object is encrypted while at rest on the server
Hack : Logging status for the S3 bucket
Hack : Make S3 bucket public readable
Hack : Make a http connection to S3 instead of https
Hack : Make an object public
Hack : Move s3 objects to Glacier
Hack : Move s3 objects to Glacier & add a Expiration
Hack : Restore an object from glacier
Hack : Search for bucket in a different AWS Region
Hack : Search for a bucket with bucket name which is case sensitive
Hack : Search for a specific bucket
Hack : Set a canned ACL for object, authenticated-read
Hack : Set a canned ACL for object, canned_bucket_owner_full_control
Hack : Set a canned ACL for object, canned_bucket_owner_read
Hack : Set a canned ACL for object, public read
Hack : Set a canned ACL for object, public read write
Hack : Set a canned ACL, authenticated-read
Hack : Set a canned ACL, private
Hack : Set a canned ACL, public-read
Hack : Set a canned ACL, public-read-write
Hack : Set a private canned ACL for an object
Hack : Set a redirect for an S3 object
Hack : Set metadata for a new s3 object on creation
Hack : Set set_request_payment for a bucket
Hack : Set the bucket Policy
Hack : Set the meta data for an object
Hack : Set up CORS for an S3 bucket
Hack : Upload a file to S3 bucket using method initiate_multipart_upload. Note should be 5MB
Hack : Upload a file to S3 bucket using method set_contents_from_filename
Hack : Upload a file to s3 bucket using the method send_file
```

```
aws s3 sync s3://developers-secret-bucket ./developers-secret-bucket
aws s3 cp s3://developers-secret-bucket ./developers-secret-bucket1 --recursive
```

```
aws dynamodb scan --table-name CardDetails

awslogs groups
awslogs streams /aws/lambda/DataExtractor
awslogs get /aws/lambda/DataExtractor
```

```bash
aws lambda list-event-source-mappings --profile main > event-source-mappings.json

aws lambda list-functions --profile main > lambda-functions.json
cat lambda-functions.json | jq -r ".Functions[] | .FunctionName" | while read -r line; do
    aws lambda list-aliases --function-name $line --profile main > lambda-$line-aliases.json
    aws lambda list-function-event-invoke-configs --function-name $line --profile main >  lambda-$line-event-invoke-configs.json

    aws lambda list-versions-by-function --function-name $line --profile main > lambda-$line-versions.json
    cat lambda-$line-versions.json | jq -r ".Versions[] | .Version" | while read -r versionline; do

        aws lambda get-function --function-name $line --qualifier "$versionline" --profile main > lambda-$line-version-$versionline.json
        
        mkdir lambda-$line-version-$versionline
        cd lambda-$line-version-$versionline
        wget `cat ../lambda-$line-version-$versionline.json |  jq -r ".Code | .Location"` -O source.zip
        unzip source.zip
        cd ..

    done
done  

aws lambda list-layers --profile main > lambda-layers.json
cat lambda-layers.json | jq -r ".Layers[] | .LayerName" | while read -r line; do
    aws lambda list-layer-versions --layer-name $line --profile main > lambda-layer-$line-versions.json

    cat lambda-layer-$line-versions.json | jq -r ".LayerVersions[] | .Version" | while read -r versionline; do
        aws lambda get-layer-version --layer-name $line --version-number $versionline --profile main > lambda-layer-$line-version-$versionline.json

        mkdir lambda-layer-$line-version-$versionline
        cd lambda-layer-$line-version-$versionline
        wget `cat ../lambda-layer-$line-version-$versionline.json | jq -r ".Content | .Location"` -O source.zip
        unzip source.zip
        cd ..
    done
done

# Diff layers 
$prev_version=''
cat lambda-layers.json | jq -r ".Layers[] | .LayerName" | while read -r line; do
    if prev_version ==  ''
        $prev_version=$line
    else
        diff -urN 
    fi
done

```
```bash

for region in `aws ec2 describe-regions --output text | cut -f4`
do
    aws ec2 describe-instances --region $region --profile student
     
    aws ec2 describe-instances-attribute --attribute usedData --instance-id $$ID$$ --region $region

    aws apigateway get-rest-apis  --region $region

    aws secretsmanager list-secrets

    aws s3 ls

    aws s3 ls s3://$$bucket-name$$ --region $region


    aws s3api list-objects --bucket $$bucket-name$$ --region $region
    aws s3api list-objects-v2 --bucket $$bucket-name$$ --region $region
    # versions of bucket
    aws s3api list-object-versions --bucket data-extractor-repo --profile student
    aws s3api list-object-versions --bucket data-extractor-repo --profile student | jq -r ".Versions[] | .VersionId"
    aws s3api get-object --bucket data-extractor-repo --key DataExtractor.zip --version-id S5l9yGDb_u0XR96U3tQexZMtmn1t6HUZ latest.zip --profile student
    
    aws --endpoint http://192.69.97.3:9000 s3api list-buckets
    aws --endpoint http://192.69.97.3:9000 s3 ls s3://hello-world
    ​aws --endpoint http://192.69.97.3:9000 s3api get-bucket-policy --bucket welcome



    aws s3 cp s3://developers-secret-bucket/dave-shared-bucket/flag.txt . --region $region
    aws s3api get-bucket-policy --bucket temporary-public-image-store --profile student

    aws lambda list-functions --region $region
    aws lambda get-function --function-name serverlessrepo-image-uploader-uploader-RM72CSUT4KDA --region $region
    aws lambda list-versions-by-function --function-name DataExtractor --profile student --region us-west-2
    # get code of a version
    aws lambda get-function --function-name DataExtractor --qualifier 1 --profile student --region us-west-2
    aws lambda  list-aliases --function-name FileUploader

    aws apigateway get-rest-apis  --region $region
    aws apigateway get-stages --rest-api-id 43iqo53xr7 --region $region
    aws apigateway get-resources --rest-api-id 43iqo53xr7 --region $region

    # https://cwlw44ht84.execute-api.ap-southeast-1.amazonaws.com/Prod
    # ;printenv to read env variables used by function
    
    # https://gist.github.com/eldondevcg/fffff4b7909351b19a53
    aws logs describe-log-groups --profile student --region us-east-1
    aws logs describe-log-streams --log-group-name /aws/lambda/DataExtractor --profile student --region us-east-1
    aws logs describe-log-streams --log-group-name /aws/lambda/DataExtractor --profile student --region us-east-1 | jq ".logStreams[] | .logStreamName"
    aws logs get-log-events --log-group-name /aws/lambda/DataExtractor --log-stream-name '2020/10/29/[$LATEST]81c6e324b37a46baa2078ba80d1f99bc' --start-time 1603674938 --profile student --region us-east-1 >> out.log
    awslogs get /aws/lambda/StressTester --profile student
    # logs might be available only when the start date is less than the time at which the log was recorded
    awslogs get /aws/lambda/StressTester --start '2d' --profile student | grep -i flag

    # dynamodb operator injection possible too
    aws dynamodb list-backups
    aws dynamodb list-tables
    aws dynamodb list-global-tables
    aws dynamodb scan --table-name CardDetails --profile student --region us-east-1

done
```