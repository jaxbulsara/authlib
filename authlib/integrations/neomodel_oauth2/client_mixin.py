from neomodel import (
    StringProperty,
    IntegerProperty,
    JSONProperty,
    StructuredNode,
)
from werkzeug.utils import cached_property
from authlib.common.encoding import json_dumps
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope


class OAuth2ClientMixin(ClientMixin):
    client_id = StringProperty(unique_index=True, max_length=48)
    client_secret = StringProperty(max_length=120)
    client_id_issued_at = IntegerProperty(required=True, default=0)
    client_secret_exipires_at = IntegerProperty(required=True, default=0)
    client_metadata_ = JSONProperty(db_property="client_metadata")

    @property
    def client_info(self):
        """Implementation for Client Info in OAuth 2.0 Dynamic Client
        Registration Protocol via `Section 3.2.1`_.

        .. _`Section 3.2.1`: https://tools.ietf.org/html/rfc7591#section-3.2.1
        """
        return dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            client_id_issued_at=self.client_id_issued_at,
            client_secret_exipires_at=self.client_secret_exipires_at,
        )

    @cached_property
    def client_metadata(self):
        return self.client_metadata_

    def set_client_metadata(self, value):
        self.client_metadata_ = value

    @property
    def redirect_uris(self):
        return self.client_metadata.get("redirect_uris", [])

    @property
    def token_endpoint_auth_method(self):
        return self.client_metadata.get(
            "token_endpoint_auth_method", "client_secret_basic"
        )

    @property
    def grant_types(self):
        return self.client_metadata.get("grant_types", [])

    @property
    def response_types(self):
        return self.client_metadata.get("response_types", [])

    @property
    def client_name(self):
        return self.client_metadata.get("client_name")

    @property
    def client_uri(self):
        return self.client_metadata.get("client_uri")

    @property
    def logo_uri(self):
        return self.client_metadata.get("logo_uri")

    @property
    def scope(self):
        return self.client_metadata.get("scope", "")

    @property
    def contacts(self):
        return self.client_metadata.get("contacts", [])

    @property
    def tos_uri(self):
        return self.client_metadata.get("tos_uri")

    @property
    def policy_uri(self):
        return self.client_metadata.get("policy_uri")

    @property
    def jwks_uri(self):
        return self.client_metadata.get("jwks_uri")

    @property
    def jwks(self):
        return self.client_metadata.get("jwks", [])

    @property
    def software_id(self):
        return self.client_metadata.get("software_id")

    @property
    def software_version(self):
        return self.client_metadata.get("software_version")

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_token_endpoint_auth_method(self, method):
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type):
        return response_type in self.response_types

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types