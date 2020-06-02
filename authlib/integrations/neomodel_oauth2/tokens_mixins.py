import time
from neomodel import (
    StructuredNode,
    StringProperty,
    IntegerProperty,
    BooleanProperty,
)
from authlib.oauth2.rfc6749 import (
    TokenMixin,
    AuthorizationCodeMixin,
)


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    code = StringProperty(max_length=120, unique_index=True, required=True)
    client_id = StringProperty(max_length=48)
    redirect_uri = StringProperty(default="")
    response_type = StringProperty(default="")
    scope = StringProperty(default="")
    nonce = StringProperty()
    auth_time = IntegerProperty(required=True, default=lambda: int(time.time()))

    code_challenge = StringProperty()
    code_challenge_method = StringProperty(max_length=48)

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time

    def get_nonce(self):
        return self.nonce


class OAuth2TokenMixin(TokenMixin):
    client_id = StringProperty(max_length=48)
    token_type = StringProperty(max_length=40)
    access_token = StringProperty(
        max_length=255, unique_index=True, required=True
    )
    refresh_token = StringProperty(max_length=255, index=True)
    scope = StringProperty(default="")
    revoked = BooleanProperty(default=False)
    issued_at = IntegerProperty(required=True, default=lambda: int(time.time()))
    expires_in = IntegerProperty(required=True, default=0)

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in
