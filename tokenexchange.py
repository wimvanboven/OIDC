from oidc import OIDC, JWT
import time

#oidc = OIDC("http://localhost:8080/auth/realms/customers/.well-known/openid-configuration", "exchange")
#oidc = OIDC("http://localhost:8080/auth/realms/customers/.well-known/openid-configuration", "test", "9f54e49a-2b49-4410-ac23-ac3bddcbbbc1")
oidc = OIDC("http://localhost:8080/auth/realms/customers/.well-known/openid-configuration", "sso", "bdc8cc10-a349-469b-b3d2-58d698797818")

certificate = '/Users/wim/Projects/Python/OIDC/certificate.pem'
key = '/Users/wim/Projects/Python/OIDC/key.rsa'

#oidc_orig.grant_client_credentials()
oidc.grant_password("wim", "wim")

at = oidc.access_token()
print(oidc.access_token().body)
rt = oidc.refresh_token()

time.sleep(65)
oidc2 = OIDC("http://localhost:8080/auth/realms/customers/.well-known/openid-configuration", "test")
oidc2.make_assertion(certificate, key)

oidc2.grant_token_exchange(at)
print(oidc2.access_token().body)


