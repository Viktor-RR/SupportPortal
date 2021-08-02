# Employees management application

### This is my first application, based on AmigoS courses and study materials. Includes:

``` mermaid
graph LR
id1[PostgreSql] --> id2[Spring Boot] --> id3[Spring Security] --> id4[JWT auth token]
                                                              --> id5[Email notification pass] --> id6[Roles and Permissions]
```

### For proper usage, change the settings below and put your valid data, where "username" - current email, and "password" is your correct password of email google account :
```java
public class EmailConstant {
    public static final String USERNAME = "";
    public static final String PASSWORD = "";
    public static final String FROM_EMAIL = "";
```
###*Dont forget to turn off security button in your google account, that provides access to applications.
###*In application.properties file you should change your configuration to database. By default - it's PostgreSQL.

