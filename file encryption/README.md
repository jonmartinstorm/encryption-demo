# File encryption
Contains
* One example encrypting a file using symmetric encryption


[Password generator](https://www.lastpass.com/password-generator)
* eZkkaMwqHqmb
* hei

Encrypt:
```
gpg --cipher-algo AES256 --symmetric top-hemmelig.pdf
```

Decrypt:
```
gpg --output top-hemmelig2.pdf --decrypt top-hemmelig.gpg
```