def create_query_client_func(client_model):
    """Create an ``query_client`` function that can be used in authorization
    server.

    :param client_model: Client model class
    """

    def query_client(client_id):
        return client_model.nodes.filter(client_id=client_id).first()

    return query_client


def create_save_token_func(token_model):
    """Create an ``save_token`` function that can be used in authorization
    server.

    :param token_model: Token model class
    """

    def save_token(token, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        item = token_model(client_id=client.client_id, user_id=user_id, **token)
        item.save()

    return save_token


def create_query_token_func(token_model):
    """Create an ``query_token`` function for revocation, introspection
    token endpoints.

    :param token_model: Token model class
    """

    def query_token(token, token_type_hint, client):
        q = token_model.nodes.filter(client_id=client.client_id, revoked=False)
        if token_type_hint == "access_token":
            return q.filter(access_token=token).first()
        elif token_type_hint == "refresh_token":
            return q.filter(refresh_token=token).first()
        # without token_type_hint
        item = q.filter(access_token=token).first()
        if item:
            return item
        return q.filter(refresh_token=token).first()

    return query_token


def create_revocation_endpoint(token_model):
    """Create a revocation endpoint class with a token model.

    :param token_model: Token model class
    """
    from authlib.oauth2.rfc7009 import RevocationEndpoint

    query_token = create_query_token_func(token_model)

    class _RevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint, client):
            return query_token(token, token_type_hint, client)

        def revoke_token(self, token):
            token.revoked = True
            token.save()

    return _RevocationEndpoint


def create_bearer_token_validator(token_model):
    """Create an bearer token validator class with a token model.

    :param token_model: Token model class
    """
    from authlib.oauth2.rfc6750 import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return token_model.nodes.filter(access_token=token_string).first()

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    return _BearerTokenValidator
