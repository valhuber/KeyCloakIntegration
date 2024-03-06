# Integration: ApiLogicServer + Keycloak

## Info

This repo contains a demo for apilogicserver integration with keycloak oidc JWT authentication.  It is an attempt to integrate this more natively into API Logic Server.

Status: not running.  See screen shot.

## Run:
```
cd devops/keycloak
docker-compose up
```

This will run keycloak on the docker host:
- keycloak (http://localhost:8080) 
    - use admin, password

## Test:

### 1. Initialize keycloak 

```bash
# keycloak realm named "kcals"
KC_BASE=http://localhost:8080/realms/kcals

# oidc token endpoint
TOKEN_ENDPOINT=$(curl ${KC_BASE}/.well-known/openid-configuration | jq -r .token_endpoint)

# retrieve an access token by logging in 
TOKEN=$(curl ${TOKEN_ENDPOINT} -d 'grant_type=password&client_id=alsclient' -d 'username=demo' -d 'password=demo' | jq -r .access_token)

# test the authentication
curl http://localhost:5656/api/Category -H "Authorization: Bearer ${TOKEN}" | jq .

```

Aside - can use this as bearer... jwt.io will decode it

```python
data = {
            "grant_type": "password",
            "client_id": "alsclient",
            "username" :f"{username}",
            "password": f"{password}"
        }
        resp = requests.post(f"{TOKEN_ENDPOINT}", data)
        if resp.status_code == 200:
            resp_data = json.loads(resp.text)
            access_token = resp_data["access_token"]
            return jsonify(access_token=access_token)
```

### 2. Start APP Logic Server

Use first Run Config.

* If possible, I'd like to simplify setup, and make debugging easier, so trying to run the app natively.

## Attempted Implementation

Several changes:

1. **Keycloak Provider:** Moved `security/authentication_provider/sql/auth_provider` to its own dir: `security/authentication_provider/keycloak/auth_provider`
    * Moved the settings and `get_jwt_pubkey` to there
    * This centralizes all the keycloak elements in 1 place
    * There is a `config/config.py` setting to activate the Keycloak Provider.
        * This will later be a CLI command.
2. Updated `security/system/authentication.py` call a new `configure_auth` function in the Keycloak Provider.
    * This removes dependency on this file to provider type.
3. Added the docker compose material (including imports) to the `devops` dir
4. Note **interim SRA** is included in `ui/safrs-react-admin`
5. To login, see the `Auth` object in the admin app


![Attempt](images/integrate-keycloak.png)


## Initial Implementation (for reference)

- the `$PWD/projects` was mounted at `/projects` in the ApiLogicServer container
- A project named [`KCALS`](projects/KCALS) was created (default nw, with authentication):

```bash
mkdir projects
chmod 777 projects # we need to be able to write to this directory from the container
docker run  $PWD/projects:/projects -it apilogicserver/api_logic_server bash -c "ApiLogicServer create --project_name=/projects/KCALS --db_url= ; ApiLogicServer add-auth --project_name=/projects/KCALS"
```

For users to be able to authenticate with JWTs signed by keycloak, we have to download the JWK signing key from keycloak and use that to validate the JWTs. 
JWT validation is implemented in [projects/KCALS/security/system/authentication.py](projects/KCALS/security/system/authentication.py). 

By default, apilogicserver authentication uses a user database. Our users are defined in keycloak however. I had to change [auth_provider.py](auth_provider.py) for this to (kinda) work.

### Change Summary

You can search for #val.

***Ignore the rest of this.***

This may not be complete - let's fix it:

| File | Notes   |
:-------|:-----------|
| config/config.py | kafka_producer property - code cleanup?? |
| security/authentication_provider/sql/auth_provider.py | get_user() - remove try, use 1st user if none (as a temp hack?)<br>Move to security/authentication_provider/kycloak/auth_provider?  |
| security/system/authentication.py | get_jwt_pubkey(): keycloak integration<br>configure_auth() pub key & algorithm settings |


## React-Admin

Nginx is used to host the safrs-react-admin frontend at http://localhost/admin-app .

## Misc Notes

Unclear why keycloak did not become a security/authentication_provider/kycloak/auth_provider?  I presume that would be the direction to go...?

    Then, `ApiLogicServer add-auth --db_url=keycloak` activates the config to use this.
        Or, `ApiLogicServer add-auth --provider=keycloak` since there is really no db

    And, move the settings and get_jwt_pubkey() to the provider...?

    In system/authentication, what causes the keycloak code to be used?  JWT_ALGORITHM setting?

    What is KCALS/auth_provider.py?  vs the one in the project...

    Presume sql models, database are not required, just came with activation?

Where is the keycloak data stored?  In the image?  So it's lost on restart?

I like the idea of not requiring image creation first - just docker compose from local files.  We will need to doc both, maybe as comments in the compose...

Can the keycloak stuff be moved into a devops directory (imports, compose)?

Does KeyCloak Admin provide a way to see the password?

Can we have a native app in addition to docker-app?


## WIP

1. added devops/keycloak
2. config - keycloak/auth_provider
3. added security/authentication_provider/keycloak/auth_provider.py
    * with attempted get_jwt_pubkey (and configs) from security/system/authentication.py
        * can authentication call this for initialization?
