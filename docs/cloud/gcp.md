Note: Following is only a sketch that need to be improved
```
* Use groups to manage permissions
* https://www.youtube.com/watch?v=x4yQY8yhVJY



Stack driver



Admin logs

Data access logs



Object versioning 

Lien flag on to make sure no deletino



CLoud Armour - SQLI etc

Edge PoP



Captcha if X number of invalid login attempts reached



Cloud KMS



Where is the Cloud SQL Root Password ? 

Cloud SQL name should  be clear enough 

Backup should be configured 

Create failover replica must be ticked



Unix domain socker muct be used for connectivity with cloud SQL : https://cloud.google.com/sql/docs/mysql/connect-app-engine



No Cloud SQL Proxies (access to DB is within the project only)



Selarate DB user should be used for connectiveity

REVOKE should be used to remove unnecessary permissions, since GCP add all permissions by default to created users 



Cloud Build must be used for deployment 

```